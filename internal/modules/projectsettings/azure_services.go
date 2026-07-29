package projectsettings

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/modules/permissions"
)

// AzureSecurityService implements supported project security REST operations.
type AzureSecurityService struct {
	groups          permissions.GroupDirectory
	projectIdentity *azure.Adapter
	security        *azure.Adapter
}

func NewAzureSecurityService(services azure.Services, groups permissions.GroupDirectory) *AzureSecurityService {
	return &AzureSecurityService{groups: groups, projectIdentity: services.ProjectIdentity, security: services.Security}
}
func (s *AzureSecurityService) ListGroups(ctx context.Context, project string) ([]permissions.Group, error) {
	if s == nil || s.groups == nil {
		return nil, fmt.Errorf("Azure security group directory is required")
	}
	return s.groups.ListGroups(ctx, project)
}
func (s *AzureSecurityService) CreateGroup(ctx context.Context, project, name string) (permissions.Group, error) {
	if s == nil || s.projectIdentity == nil {
		return permissions.Group{}, fmt.Errorf("Azure project identity adapter is required")
	}
	query := url.Values{"__v": {"5"}}
	body := map[string]string{"name": name, "description": "", "tfid": ""}
	if err := s.projectIdentity.Do(ctx, azure.Request{Project: project, Method: http.MethodPost, Path: "ManageGroup", Query: query, Body: body}, nil); err != nil {
		return permissions.Group{}, err
	}
	groups, err := permissions.NewAzureGroupDirectory(s.projectIdentity).ListGroups(ctx, project)
	if err != nil {
		return permissions.Group{}, err
	}
	for _, group := range groups {
		if group.Name == name {
			return group, nil
		}
	}
	return permissions.Group{}, fmt.Errorf("created group %q was not returned by Azure DevOps", name)
}
func (s *AzureSecurityService) ReadProjectAccess(context.Context, string) (AccessSnapshot, error) {
	return AccessSnapshot{}, azure.Unsupported(azure.Security, "read project permission state")
}
func (s *AzureSecurityService) SetProjectAccess(context.Context, string, []permissions.AccessChange) error {
	return azure.Unsupported(azure.Security, "set project permission state")
}

// Unsupported adapters explicitly reject project settings without a verified public Server 2022.2 endpoint.
type UnsupportedSettingsService struct{}

func (UnsupportedSettingsService) ReadPipelineSettings(context.Context, string) (config.PipelineSettingsConfig, error) {
	return config.PipelineSettingsConfig{}, azure.Unsupported(azure.Build, "read pipeline project settings")
}
func (UnsupportedSettingsService) SetPipelineSettings(context.Context, string, config.PipelineSettingsConfig) error {
	return azure.Unsupported(azure.Build, "set pipeline project settings")
}

type UnsupportedOverviewService struct{}

func (UnsupportedOverviewService) ReadOverview(context.Context, string) (config.OverviewConfig, error) {
	return config.OverviewConfig{}, azure.Unsupported(azure.Projects, "read project feature states")
}
func (UnsupportedOverviewService) SetOverview(context.Context, string, config.OverviewConfig) error {
	return azure.Unsupported(azure.Projects, "set project feature states")
}
