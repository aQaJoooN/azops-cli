package projectsettings

import (
	"context"

	"azops-cli/internal/config"
	"azops-cli/internal/modules/permissions"
)

// AccessSnapshot is the current access state and namespace bit mapping.
type AccessSnapshot struct {
	Bits   map[config.PermissionName]permissions.AccessBit
	Values map[string]map[permissions.AccessBit]config.AccessValue
	// PermEntries holds the full Display permission metadata per name,
	// used by SetProjectAccess to resolve the correct token/namespaceId.
	PermEntries map[config.PermissionName]displayPermission
}

// SecurityService manages project groups and project-level access.
type SecurityService interface {
	permissions.GroupDirectory
	CreateGroup(context.Context, string, string) (permissions.Group, error)
	ReadProjectAccess(context.Context, string) (AccessSnapshot, error)
	SetProjectAccess(context.Context, string, []permissions.AccessChange) error
}

// RepositoryState is the managed repository policy and access state.
type RepositoryState struct {
	MaximumFileSize string
	Access          AccessSnapshot
}

type RepositoryService interface {
	ReadRepositoryState(context.Context, string) (RepositoryState, error)
	SetMaximumFileSize(context.Context, string, string) error
	SetRepositoryAccess(context.Context, string, []permissions.AccessChange) error
}

// DashboardService manages project dashboard security flags.
type DashboardService interface {
	ReadDashboardSecurity(context.Context, string) (config.DashboardSecurity, error)
	SetDashboardSecurity(context.Context, string, config.DashboardSecurity) error
}

// AgentPoolService manages project-scoped pool role assignments.
type AgentPoolService interface {
	ReadAgentPoolRoles(context.Context, string, string) (map[string]config.Role, error)
	SetAgentPoolRoles(context.Context, string, string, []permissions.RoleChange) error
}

// ReleaseService manages project release-retention settings.
type ReleaseService interface {
	ReadReleaseRetention(context.Context, string) (config.ReleaseRetentionConfig, error)
	SetReleaseRetention(context.Context, string, config.ReleaseRetentionConfig) error
}

// TestService manages project test-retention settings.
type TestService interface {
	ReadTestRetention(context.Context, string) (config.TestRetentionConfig, error)
	SetTestRetention(context.Context, string, config.TestRetentionConfig) error
}

// ServiceConnection is the non-sensitive current-state representation.
type ServiceConnection struct {
	Name, Type, URL, Auth string
	GrantAccess           bool
}
type ServiceConnectionService interface {
	ListServiceConnections(context.Context, string) ([]ServiceConnection, error)
	UpsertServiceConnection(context.Context, string, config.ServiceConnectionSecret) error
	ReadServiceConnectionRoles(context.Context, string) (map[string]config.Role, error)
	SetServiceConnectionRoles(context.Context, string, []permissions.RoleChange) error
}

// ServiceHook is the non-sensitive current-state representation.
type ServiceHook struct{ ID, Name, Event, URL string }
type ServiceHookService interface {
	ListServiceHooks(context.Context, string) ([]ServiceHook, error)
	UpsertServiceHook(context.Context, string, string, config.ServiceHookSecret) error
}

// SettingsService manages build/pipeline project settings.
type SettingsService interface {
	ReadPipelineSettings(context.Context, string) (config.PipelineSettingsConfig, error)
	SetPipelineSettings(context.Context, string, config.PipelineSettingsConfig) error
}

// OverviewService manages project feature states.
type OverviewService interface {
	ReadOverview(context.Context, string) (config.OverviewConfig, error)
	SetOverview(context.Context, string, config.OverviewConfig) error
}
