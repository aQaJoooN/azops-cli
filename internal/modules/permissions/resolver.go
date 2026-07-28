package permissions

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"azops-cli/internal/config"
)

const AllGroups config.GroupSelector = "all"

// Principal is one configured alias resolved to an Azure DevOps group.
type Principal struct {
	Alias      config.GroupSelector
	Name       string
	Descriptor string
}

// Resolver expands configured aliases and caches directory results for one run.
type Resolver struct {
	project   string
	template  string
	aliases   map[config.GroupSelector]string
	directory GroupDirectory

	once      sync.Once
	groups    []Group
	loadError error
}

func NewResolver(general config.GeneralConfig, directory GroupDirectory) (*Resolver, error) {
	aliases := make(map[config.GroupSelector]string)
	for team, roles := range general.GroupsAlias {
		for role, id := range roles {
			alias := config.GroupSelector(id)
			if id == "" || id == string(AllGroups) {
				return nil, fmt.Errorf("invalid group alias %q for %s/%s", id, team, role)
			}
			if _, exists := aliases[alias]; exists {
				return nil, fmt.Errorf("duplicate group alias %q", id)
			}
			name, err := ExpandGroupName(general.GroupNameTemplate, general.TeamProjectName, team, role)
			if err != nil {
				return nil, err
			}
			aliases[alias] = name
		}
	}
	return &Resolver{project: general.TeamProjectName, template: general.GroupNameTemplate, aliases: aliases, directory: directory}, nil
}

func ExpandGroupName(template, project, team, role string) (string, error) {
	if strings.TrimSpace(template) == "" {
		return "", fmt.Errorf("group name template is required")
	}
	if !strings.Contains(template, "teamprojectname") {
		return "", fmt.Errorf("group name template is missing %q", "teamprojectname")
	}
	withoutProject := strings.ReplaceAll(template, "teamprojectname", "")
	if !strings.Contains(withoutProject, "team") {
		return "", fmt.Errorf("group name template is missing %q", "team")
	}
	if !strings.Contains(template, "role") {
		return "", fmt.Errorf("group name template is missing %q", "role")
	}
	name := strings.NewReplacer(
		"teamprojectname", project,
		"team", team,
		"role", role,
	).Replace(template)
	return strings.TrimSpace(name), nil
}

func (resolver *Resolver) Resolve(ctx context.Context, selectors []config.GroupSelector) ([]Principal, error) {
	if resolver == nil || resolver.directory == nil {
		return nil, fmt.Errorf("group resolver requires a directory")
	}
	resolver.once.Do(func() { resolver.groups, resolver.loadError = resolver.directory.ListGroups(ctx) })
	if resolver.loadError != nil {
		return nil, resolver.loadError
	}

	byName := make(map[string]Group, len(resolver.groups))
	for _, group := range resolver.groups {
		if previous, exists := byName[group.Name]; exists && previous.Descriptor != group.Descriptor {
			return nil, fmt.Errorf("group name %q resolves to multiple descriptors", group.Name)
		}
		byName[group.Name] = group
	}

	principals := make(map[string]Principal)
	add := func(alias config.GroupSelector, group Group) {
		if _, exists := principals[group.Descriptor]; !exists {
			principals[group.Descriptor] = Principal{Alias: alias, Name: group.Name, Descriptor: group.Descriptor}
		}
	}
	for _, selector := range selectors {
		if selector == AllGroups {
			for alias, name := range resolver.aliases {
				group, exists := byName[name]
				if !exists {
					return nil, fmt.Errorf("group alias %q resolves to missing Azure DevOps group %q", alias, name)
				}
				add(alias, group)
			}
			for _, group := range resolver.groups {
				if strings.HasPrefix(group.Name, resolver.project) {
					add(AllGroups, group)
				}
			}
			continue
		}
		name, exists := resolver.aliases[selector]
		if !exists {
			return nil, fmt.Errorf("group alias %q is not configured", selector)
		}
		group, exists := byName[name]
		if !exists {
			return nil, fmt.Errorf("group alias %q resolves to missing Azure DevOps group %q", selector, name)
		}
		add(selector, group)
	}

	result := make([]Principal, 0, len(principals))
	for _, principal := range principals {
		result = append(result, principal)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].Descriptor < result[j].Descriptor
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}
