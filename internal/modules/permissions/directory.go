package permissions

import (
	"context"
	"fmt"

	"azops-cli/internal/azure"
)

// Group is the principal data required by permission reconciliation.
type Group struct {
	Name       string
	Descriptor string
}

// GroupDirectory lists Azure DevOps groups visible to the collection.
type GroupDirectory interface {
	ListGroups(context.Context) ([]Group, error)
}

// AzureGroupDirectory reads groups through the Azure DevOps Graph API.
type AzureGroupDirectory struct {
	adapter *azure.Adapter
}

func NewAzureGroupDirectory(adapter *azure.Adapter) *AzureGroupDirectory {
	return &AzureGroupDirectory{adapter: adapter}
}

func (directory *AzureGroupDirectory) ListGroups(ctx context.Context) ([]Group, error) {
	if directory == nil || directory.adapter == nil {
		return nil, fmt.Errorf("group directory requires a graph adapter")
	}
	var response struct {
		Value []struct {
			DisplayName string `json:"displayName"`
			Descriptor  string `json:"descriptor"`
		} `json:"value"`
	}
	if err := directory.adapter.Do(ctx, azure.Request{Path: "groups"}, &response); err != nil {
		return nil, fmt.Errorf("list Azure DevOps groups: %w", err)
	}
	groups := make([]Group, 0, len(response.Value))
	for _, item := range response.Value {
		if item.DisplayName == "" || item.Descriptor == "" {
			return nil, fmt.Errorf("Azure DevOps group response contains an empty name or descriptor")
		}
		groups = append(groups, Group{Name: item.DisplayName, Descriptor: item.Descriptor})
	}
	return groups, nil
}
