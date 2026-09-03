package main

import (
	"context"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/detector"
	"azops-cli/internal/modules/permissions"
	"azops-cli/internal/modules/pipelines"
	"azops-cli/internal/modules/projectsettings"
)

func applicationDependencies(services azure.Services) detector.Dependencies {
	directory := permissions.NewCachedGroupDirectory(permissions.NewAzureGroupDirectory(services.ProjectIdentity))
	unsupported := unsupportedServices{}
	return detector.Dependencies{
		GroupDirectory:     directory,
		Security:           projectsettings.NewAzureSecurityService(services, directory),
		Repositories:       projectsettings.NewAzureRepositoryService(services),
		Dashboards:         projectsettings.NewAzureDashboardService(services),
		AgentPools:         projectsettings.NewAzureAgentPoolService(services, directory),
		Release:            unsupported,
		ServiceConnections: projectsettings.NewAzureServiceConnectionService(services, directory),
		Test:               projectsettings.NewAzureTestService(services),
		ServiceHook:        projectsettings.NewAzureServiceHookService(services),
		Settings:           projectsettings.NewAzureSettingsService(services),
		Overview:           projectsettings.UnsupportedOverviewService{},
		Environments:       pipelines.NewAzureEnvironmentService(services, directory),
		Library:            pipelines.NewAzureLibraryService(services, directory),
		TaskGroups:         pipelines.NewAzureTaskGroupService(services),
		DeploymentGroup:    pipelines.NewAzureDeploymentGroupService(services),
		PipelineAccess:     pipelines.NewAzurePipelineScopedService(services),
		ReleaseAccess:      pipelines.NewAzureReleaseScopedService(services),
	}
}

type unsupportedServices struct{}

func (unsupportedServices) ReadReleaseRetention(context.Context, string) (config.ReleaseRetentionConfig, error) {
	return config.ReleaseRetentionConfig{}, azure.Unsupported(azure.Release, "read release retention")
}
func (unsupportedServices) SetReleaseRetention(context.Context, string, config.ReleaseRetentionConfig) error {
	return azure.Unsupported(azure.Release, "set release retention")
}
func (unsupportedServices) ReadTestRetention(context.Context, string) (config.TestRetentionConfig, error) {
	return config.TestRetentionConfig{}, azure.Unsupported(azure.Test, "read test retention")
}
func (unsupportedServices) SetTestRetention(context.Context, string, config.TestRetentionConfig) error {
	return azure.Unsupported(azure.Test, "set test retention")
}
func (unsupportedServices) ListServiceHooks(context.Context, string) ([]projectsettings.ServiceHook, error) {
	return nil, azure.Unsupported(azure.ServiceHooks, "list service hooks")
}
func (unsupportedServices) UpsertServiceHook(context.Context, string, string, config.ServiceHookSecret) error {
	return azure.Unsupported(azure.ServiceHooks, "upsert service hook")
}
func (unsupportedServices) ReadEnvironmentRoles(context.Context, string) (map[string]config.Role, error) {
	return nil, azure.Unsupported(azure.DistributedTask, "read environment roles")
}
func (unsupportedServices) SetEnvironmentRoles(context.Context, string, []permissions.RoleChange) error {
	return azure.Unsupported(azure.DistributedTask, "set environment roles")
}
func (unsupportedServices) ListVariableGroups(context.Context, string) ([]pipelines.VariableGroup, error) {
	return nil, azure.Unsupported(azure.DistributedTask, "list variable groups")
}
func (unsupportedServices) UpsertVariableGroup(context.Context, string, config.VariableGroupSecret) error {
	return azure.Unsupported(azure.DistributedTask, "upsert variable group")
}
func (unsupportedServices) ReadLibraryRoles(context.Context, string) (map[string]config.Role, error) {
	return nil, azure.Unsupported(azure.DistributedTask, "read library roles")
}
func (unsupportedServices) SetLibraryRoles(context.Context, string, []permissions.RoleChange) error {
	return azure.Unsupported(azure.DistributedTask, "set library roles")
}
func (unsupportedServices) ReadTaskGroupAccess(context.Context, string) (pipelines.AccessSnapshot, error) {
	return pipelines.AccessSnapshot{}, azure.Unsupported(azure.DistributedTask, "read task group permissions")
}
func (unsupportedServices) SetTaskGroupAccess(context.Context, string, []permissions.AccessChange) error {
	return azure.Unsupported(azure.DistributedTask, "set task group permissions")
}
func (unsupportedServices) ReadDeploymentGroupRoles(context.Context, string) (map[string]config.Role, error) {
	return nil, azure.Unsupported(azure.DistributedTask, "read deployment group roles")
}
func (unsupportedServices) SetDeploymentGroupRoles(context.Context, string, []permissions.RoleChange) error {
	return azure.Unsupported(azure.DistributedTask, "set deployment group roles")
}
