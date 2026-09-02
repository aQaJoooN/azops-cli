package pipelines

import (
	"context"

	"azops-cli/internal/config"
	"azops-cli/internal/modules/permissions"
)

// EnvironmentService manages project-wide environment role assignments.
type EnvironmentService interface {
	ReadEnvironmentRoles(context.Context, string) (map[string]config.Role, error)
	SetEnvironmentRoles(context.Context, string, []permissions.RoleChange) error
}

// VariableGroup is the managed, potentially sensitive state of one library variable group.
type VariableGroup struct {
	Name      string
	Variables map[string]string
}

// LibraryService manages selected variable groups and project-wide library roles.
type LibraryService interface {
	ListVariableGroups(context.Context, string) ([]VariableGroup, error)
	UpsertVariableGroup(context.Context, string, config.VariableGroupSecret) error
	ReadLibraryRoles(context.Context, string) (map[string]config.Role, error)
	SetLibraryRoles(context.Context, string, []permissions.RoleChange) error
}

// AccessSnapshot is the current permission state and namespace bit mapping.
type AccessSnapshot struct {
	Bits   map[config.PermissionName]permissions.AccessBit
	Values map[string]map[permissions.AccessBit]config.AccessValue
}

// TaskGroupService manages project-wide task-group access assignments.
type TaskGroupService interface {
	ReadTaskGroupAccess(context.Context, string) (AccessSnapshot, error)
	SetTaskGroupAccess(context.Context, string, []permissions.AccessChange) error
}

// DeploymentGroupService manages project-wide deployment-group roles.
type DeploymentGroupService interface {
	ReadDeploymentGroupRoles(context.Context, string) (map[string]config.Role, error)
	SetDeploymentGroupRoles(context.Context, string, []permissions.RoleChange) error
}

// ScopedPermissionService manages access assignments at canonical root or folder paths.
// changes contains only the assignments that differ from the current state.
// allACEs contains the full desired ACE set for every principal in the config
// (including Not_Set entries); it is non-nil for sub-folder paths and is used
// to write explicit zero-bit entries so groups cannot inherit from the root.
type ScopedPermissionService interface {
	ReadScopedAccess(context.Context, string, string) (AccessSnapshot, error)
	SetScopedAccess(ctx context.Context, project, path string, changes []permissions.AccessChange, allACEs []permissions.AccessChange) error
}
