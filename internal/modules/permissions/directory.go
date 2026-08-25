package permissions

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"azops-cli/internal/azure"
)

// Group is the principal data required by permission reconciliation.
type Group struct {
	Name       string
	Descriptor string
	TFID       string // TeamFoundationId GUID, used for internal identity API calls
}

// GroupCacheInvalidator can be implemented by a GroupDirectory that supports cache invalidation.
type GroupCacheInvalidator interface {
	Invalidate(project string)
}

// GroupDirectory lists Azure DevOps groups visible to one project.
type GroupDirectory interface {
	ListGroups(context.Context, string) ([]Group, error)
}

// AzureGroupDirectory reads groups through the project-scoped identity API
// exposed by Azure DevOps Server installations without the Graph API.
type AzureGroupDirectory struct {
	adapter *azure.Adapter
}

func NewAzureGroupDirectory(adapter *azure.Adapter) *AzureGroupDirectory {
	return &AzureGroupDirectory{adapter: adapter}
}

func (directory *AzureGroupDirectory) ListGroups(ctx context.Context, project string) ([]Group, error) {
	if directory == nil || directory.adapter == nil {
		return nil, fmt.Errorf("group directory requires a project identity adapter")
	}
	var response struct {
		Identities []struct {
			Name string `json:"FriendlyDisplayName"`
			ID   string `json:"TeamFoundationId"`
		} `json:"identities"`
	}
	query := url.Values{"__v": {"5"}}
	if err := directory.adapter.Do(ctx, azure.Request{Project: project, Path: "ReadScopedApplicationGroupsJson", Query: query}, &response); err != nil {
		return nil, fmt.Errorf("list Azure DevOps groups: %w", err)
	}
	groups := make([]Group, 0, len(response.Identities))
	for _, item := range response.Identities {
		if item.Name == "" || item.ID == "" {
			return nil, fmt.Errorf("Azure DevOps group response contains an empty name or ID")
		}
		var display struct {
			Security struct {
				IdentityType string `json:"descriptorIdentityType"`
				Identifier   string `json:"descriptorIdentifier"`
			} `json:"security"`
		}
		displayQuery := url.Values{"__v": {"5"}, "tfid": {item.ID}}
		if err := directory.adapter.Do(ctx, azure.Request{Project: project, Path: "Display", Query: displayQuery}, &display); err != nil {
			return nil, fmt.Errorf("read Azure DevOps group %q: %w", item.Name, err)
		}
		if display.Security.IdentityType == "" || display.Security.Identifier == "" {
			return nil, fmt.Errorf("Azure DevOps group %q has no security descriptor", item.Name)
		}
		groups = append(groups, Group{Name: item.Name, Descriptor: display.Security.IdentityType + ";" + display.Security.Identifier, TFID: item.ID})
	}
	return groups, nil
}

// CachedGroupDirectory shares one immutable group snapshot across all modules
// in an application run.
type cachedGroups struct {
	once   sync.Once
	groups []Group
	err    error
}

type CachedGroupDirectory struct {
	source GroupDirectory
	mu     sync.Mutex
	cache  map[string]*cachedGroups
}

func NewCachedGroupDirectory(source GroupDirectory) *CachedGroupDirectory {
	return &CachedGroupDirectory{source: source, cache: make(map[string]*cachedGroups)}
}

// Invalidate clears the cached group list for a project so the next call re-fetches.
func (directory *CachedGroupDirectory) Invalidate(project string) {
	if directory == nil {
		return
	}
	directory.mu.Lock()
	delete(directory.cache, project)
	directory.mu.Unlock()
}

func (directory *CachedGroupDirectory) ListGroups(ctx context.Context, project string) ([]Group, error) {
	if directory == nil || directory.source == nil {
		return nil, fmt.Errorf("cached group directory requires a source")
	}
	directory.mu.Lock()
	entry := directory.cache[project]
	if entry == nil {
		entry = &cachedGroups{}
		directory.cache[project] = entry
	}
	directory.mu.Unlock()
	entry.once.Do(func() {
		entry.groups, entry.err = directory.source.ListGroups(ctx, project)
		entry.groups = append([]Group(nil), entry.groups...)
	})
	return append([]Group(nil), entry.groups...), entry.err
}
