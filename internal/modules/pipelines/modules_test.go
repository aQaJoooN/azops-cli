package pipelines

import (
	"context"
	"errors"
	"strings"
	"testing"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type groupMemory []permissions.Group

func (groups groupMemory) ListGroups(context.Context, string) ([]permissions.Group, error) {
	return append([]permissions.Group(nil), groups...), nil
}

func pipelineGeneral() config.GeneralConfig {
	return config.GeneralConfig{
		TeamProjectName:   "project",
		GroupNameTemplate: "teamprojectname team role",
		GroupsAlias:       map[string]map[string]string{"Dev": {"Readers": "11"}},
	}
}

func pipelineGroups() groupMemory {
	return groupMemory{{Name: "project Dev Readers", Descriptor: "group-11"}}
}

type taskGroupMemory struct {
	access AccessSnapshot
	writes [][]permissions.AccessChange
}

func (service *taskGroupMemory) ReadTaskGroupAccess(context.Context, string) (AccessSnapshot, error) {
	return service.access, nil
}

func (service *taskGroupMemory) SetTaskGroupAccess(_ context.Context, _ string, changes []permissions.AccessChange) error {
	service.writes = append(service.writes, append([]permissions.AccessChange(nil), changes...))
	return nil
}
func taskGroupInput() domain.ModuleInput {
	return domain.ModuleInput{DesiredState: config.Config{
		General: pipelineGeneral(),
		Pipelines: config.PipelinesConfig{TaskGroups: &config.AccessPermissionsConfig{Permissions: config.AccessAssignments{
			"View": {config.AccessAllow: {"11"}},
		}}},
	}}
}

func TestTaskGroupsNoOpAndChangedApply(t *testing.T) {
	service := &taskGroupMemory{access: AccessSnapshot{
		Bits:   map[config.PermissionName]permissions.AccessBit{"View": 1},
		Values: map[string]map[permissions.AccessBit]config.AccessValue{"group-11": {1: config.AccessAllow}},
	}}
	module := NewTaskGroups(service, pipelineGroups())
	plan, err := module.Plan(context.Background(), taskGroupInput())
	if err != nil || len(plan.Operations) != 0 {
		t.Fatalf("equal state plan = %#v, %v", plan, err)
	}

	service.access.Values["group-11"][1] = config.AccessDeny
	plan, err = module.Plan(context.Background(), taskGroupInput())
	if err != nil || len(plan.Operations) != 1 {
		t.Fatalf("changed state plan = %#v, %v", plan, err)
	}
	result, err := module.Apply(context.Background(), plan)
	if err != nil || len(result.Changes) != 1 || len(service.writes) != 1 {
		t.Fatalf("apply = %#v, writes %#v, %v", result, service.writes, err)
	}
}

type roleMemory struct {
	roles  map[string]config.Role
	writes [][]permissions.RoleChange
}

func (service *roleMemory) ReadEnvironmentRoles(context.Context, string) (map[string]config.Role, error) {
	return service.roles, nil
}

func (service *roleMemory) SetEnvironmentRoles(_ context.Context, _ string, changes []permissions.RoleChange) error {
	service.writes = append(service.writes, append([]permissions.RoleChange(nil), changes...))
	return nil
}

func TestEnvironmentRoleReconciliation(t *testing.T) {
	service := &roleMemory{roles: map[string]config.Role{"group-11": config.RoleReader}}
	module := NewEnvironments(service, pipelineGroups())
	input := domain.ModuleInput{DesiredState: config.Config{
		General: pipelineGeneral(),
		Pipelines: config.PipelinesConfig{Environments: &config.RolePermissionsConfig{Permissions: config.RoleAssignments{
			config.RoleAdministrator: {"11"},
		}}},
	}}
	plan, err := module.Plan(context.Background(), input)
	if err != nil || len(plan.Operations) != 1 {
		t.Fatalf("role plan = %#v, %v", plan, err)
	}
	result, err := module.Apply(context.Background(), plan)
	if err != nil || len(result.Changes) != 1 || len(service.writes) != 1 {
		t.Fatalf("role apply = %#v, writes %#v, %v", result, service.writes, err)
	}
	change := service.writes[0][0]
	if change.Principal.Descriptor != "group-11" || change.Current != config.RoleReader || change.Desired != config.RoleAdministrator {
		t.Fatalf("unexpected role change %#v", change)
	}
}

type scopedMemory struct {
	access    AccessSnapshot
	readPaths []string
	setPaths  []string
}

func (service *scopedMemory) ReadScopedAccess(_ context.Context, _, path string) (AccessSnapshot, error) {
	service.readPaths = append(service.readPaths, path)
	return service.access, nil
}

func (service *scopedMemory) SetScopedAccess(_ context.Context, _, path string, _ []permissions.AccessChange) error {
	service.setPaths = append(service.setPaths, path)
	return nil
}

func TestPipelineScopedPathIsCanonical(t *testing.T) {
	service := &scopedMemory{access: AccessSnapshot{
		Bits: map[config.PermissionName]permissions.AccessBit{"View": 1}, Values: map[string]map[permissions.AccessBit]config.AccessValue{},
	}}
	module := NewPipelines(service, pipelineGroups())
	input := domain.ModuleInput{DesiredState: config.Config{
		General: pipelineGeneral(),
		Pipelines: config.PipelinesConfig{Pipelines: &config.ScopedPermissionsConfig{Permissions: []config.ScopedPermissions{{
			Path:       ` folder\child/ `,
			Permission: config.AccessAssignments{"View": {config.AccessAllow: {"11"}}},
		}}}},
	}}
	plan, err := module.Plan(context.Background(), input)
	if err != nil || len(plan.Operations) != 1 || plan.Operations[0].Resource != "/folder/child" {
		t.Fatalf("scoped plan = %#v, %v", plan, err)
	}
	_, err = module.Apply(context.Background(), plan)
	if err != nil || len(service.readPaths) != 1 || service.readPaths[0] != "/folder/child" || len(service.setPaths) != 1 || service.setPaths[0] != "/folder/child" {
		t.Fatalf("paths read %#v, set %#v, error %v", service.readPaths, service.setPaths, err)
	}
}

type libraryMemory struct {
	groups  []VariableGroup
	written []config.VariableGroupSecret
}

func (service *libraryMemory) ListVariableGroups(context.Context, string) ([]VariableGroup, error) {
	return service.groups, nil
}

func (service *libraryMemory) UpsertVariableGroup(_ context.Context, _ string, secret config.VariableGroupSecret) error {
	service.written = append(service.written, secret)
	return nil
}

func (service *libraryMemory) ReadLibraryRoles(context.Context, string) (map[string]config.Role, error) {
	return map[string]config.Role{}, nil
}

func (service *libraryMemory) SetLibraryRoles(context.Context, string, []permissions.RoleChange) error {
	return nil
}

func TestLibraryPlanAndResultAreSecretSafe(t *testing.T) {
	const secretValue = "library-password"
	service := &libraryMemory{}
	module := NewLibrary(service, pipelineGroups())
	input := domain.ModuleInput{
		DesiredState: config.Config{General: pipelineGeneral(), Pipelines: config.PipelinesConfig{Library: &config.LibraryConfig{Create: []string{"shared"}}}},
		SecretState: config.Secrets{Pipelines: config.PipelineSecrets{Library: []config.VariableGroupSecret{{
			Name: "shared", Variables: []config.SecretVariable{{Name: "password", Value: secretValue}},
		}}}},
	}
	plan, err := module.Plan(context.Background(), input)
	if err != nil || len(plan.Operations) != 1 {
		t.Fatalf("library plan = %#v, %v", plan, err)
	}
	if strings.Contains(plan.Operations[0].Summary, secretValue) {
		t.Fatalf("plan summary disclosed secret: %q", plan.Operations[0].Summary)
	}
	result, err := module.Apply(context.Background(), plan)
	if err != nil || len(result.Changes) != 1 || len(service.written) != 1 {
		t.Fatalf("library apply = %#v, writes %#v, %v", result, service.written, err)
	}
	if strings.Contains(result.Changes[0].Summary, secretValue) {
		t.Fatalf("result summary disclosed secret: %q", result.Changes[0].Summary)
	}
}

type unsupportedTaskGroups struct{}

func (unsupportedTaskGroups) ReadTaskGroupAccess(context.Context, string) (AccessSnapshot, error) {
	return AccessSnapshot{}, azure.Unsupported(azure.DistributedTask, "read task group permissions")
}

func (unsupportedTaskGroups) SetTaskGroupAccess(context.Context, string, []permissions.AccessChange) error {
	return azure.Unsupported(azure.DistributedTask, "set task group permissions")
}

func TestUnsupportedPipelineCapabilityIsTyped(t *testing.T) {
	module := NewTaskGroups(unsupportedTaskGroups{}, pipelineGroups())
	_, err := module.Plan(context.Background(), taskGroupInput())
	var unsupported *azure.UnsupportedOperationError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected unsupported operation, got %v", err)
	}
	var moduleErr *domain.ModuleError
	if !errors.As(err, &moduleErr) || moduleErr.Component != "pipelines.taskgroups" {
		t.Fatalf("expected task-group module context, got %v", err)
	}
}
