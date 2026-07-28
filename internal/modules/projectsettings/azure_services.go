package projectsettings

import (
	"context"
	"fmt"
	"net/http"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/modules/permissions"
)

// AzureSecurityService implements supported project security REST operations.
type AzureSecurityService struct{ graph, security *azure.Adapter }

func NewAzureSecurityService(services azure.Services) *AzureSecurityService {
	return &AzureSecurityService{services.Graph, services.Security}
}
func (s *AzureSecurityService) ListGroups(ctx context.Context) ([]permissions.Group, error) {
	return permissions.NewAzureGroupDirectory(s.graph).ListGroups(ctx)
}
func (s *AzureSecurityService) CreateGroup(ctx context.Context, name string) (permissions.Group, error) {
	var out struct{ DisplayName, Descriptor string }
	err := s.graph.Do(ctx, azure.Request{Method: http.MethodPost, Path: "groups", Body: map[string]string{"displayName": name}}, &out)
	if err != nil {
		return permissions.Group{}, err
	}
	if out.Descriptor == "" {
		return permissions.Group{}, fmt.Errorf("created group %q has no descriptor", name)
	}
	return permissions.Group{Name: name, Descriptor: out.Descriptor}, nil
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
