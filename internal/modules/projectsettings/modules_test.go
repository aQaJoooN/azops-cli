package projectsettings

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

type dashboardMemory struct {
	state  config.DashboardSecurity
	err    error
	writes int
}

func (s *dashboardMemory) ReadDashboardSecurity(context.Context, string) (config.DashboardSecurity, error) {
	return s.state, s.err
}
func (s *dashboardMemory) SetDashboardSecurity(_ context.Context, _ string, v config.DashboardSecurity) error {
	s.state = v
	s.writes++
	return nil
}

type hookMemory struct {
	current  []ServiceHook
	written  []config.ServiceHookSecret
	writeErr error
}

func (s *hookMemory) ListServiceHooks(context.Context, string) ([]ServiceHook, error) {
	return s.current, nil
}
func (s *hookMemory) UpsertServiceHook(_ context.Context, _, _ string, v config.ServiceHookSecret) error {
	s.written = append(s.written, v)
	return s.writeErr
}

func dashboardInput(value config.DashboardSecurity) domain.ModuleInput {
	return domain.ModuleInput{DesiredState: config.Config{General: config.GeneralConfig{TeamProjectName: "project"}, ProjectSettings: config.ProjectSettingsConfig{Dashboards: &config.DashboardsConfig{Security: value}}}}
}

func TestDashboardNoOpAndApply(t *testing.T) {
	desired := config.DashboardSecurity{Create: true, Edit: true}
	service := &dashboardMemory{state: desired}
	module := NewDashboards(service)
	plan, err := module.Plan(context.Background(), dashboardInput(desired))
	if err != nil || len(plan.Operations) != 0 {
		t.Fatalf("equal state plan = %#v, %v", plan, err)
	}
	changed := config.DashboardSecurity{Create: true, Edit: true, Delete: true}
	plan, err = module.Plan(context.Background(), dashboardInput(changed))
	if err != nil || len(plan.Operations) != 1 {
		t.Fatalf("changed state plan = %#v, %v", plan, err)
	}
	result, err := module.Apply(context.Background(), plan)
	if err != nil || service.writes != 1 || len(result.Changes) != 1 {
		t.Fatalf("apply = %#v, writes %d, %v", result, service.writes, err)
	}
}

func TestServiceHookPlanIsSecretSafe(t *testing.T) {
	service := &hookMemory{}
	module := NewServiceHook(service)
	secret := config.ServiceHookSecret{Name: "hook", Event: "Pull request created", URL: "https://user:password@example.invalid/private"}
	input := domain.ModuleInput{DesiredState: config.Config{General: config.GeneralConfig{TeamProjectName: "project"}, ProjectSettings: config.ProjectSettingsConfig{ServiceHook: &config.CreateConfig{Create: []string{"hook"}}}}, SecretState: config.Secrets{ProjectSettings: config.ProjectSettingsSecrets{ServiceHooks: []config.ServiceHookSecret{secret}}}}
	plan, err := module.Plan(context.Background(), input)
	if err != nil || len(plan.Operations) != 1 {
		t.Fatalf("plan = %#v, %v", plan, err)
	}
	if strings.Contains(plan.Operations[0].Summary, "password") || strings.Contains(plan.Operations[0].Summary, secret.URL) {
		t.Fatalf("summary disclosed secret: %q", plan.Operations[0].Summary)
	}
	result, err := module.Apply(context.Background(), plan)
	if err != nil || len(result.Changes) != 1 || len(service.written) != 1 {
		t.Fatalf("apply = %#v, %v", result, err)
	}
}

func TestServiceHookPlanRequiresExactlyOneSameNameSecret(t *testing.T) {
	secret := config.ServiceHookSecret{Name: "hook", Event: "Pull request created", URL: "https://example.invalid/hook"}
	input := serviceHookInput(secret)
	input.SecretState = config.Secrets{ProjectSettings: config.ProjectSettingsSecrets{ServiceHooks: []config.ServiceHookSecret{secret, secret}}}

	_, err := NewServiceHook(&hookMemory{}).Plan(context.Background(), input)
	if err == nil || !strings.Contains(err.Error(), "exactly one is required") {
		t.Fatalf("expected duplicate same-name secret error, got %v", err)
	}
}

func TestServiceHookApplyRedactsSecretValuesFromErrors(t *testing.T) {
	secret := config.ServiceHookSecret{Name: "private", Event: "private event", URL: "https://user:password@example.invalid/private"}
	service := &hookMemory{writeErr: errors.New("rejected " + secret.Name + " " + secret.Event + " at " + secret.URL)}
	module := NewServiceHook(service)
	plan := domain.Plan{Module: module.ID(), Component: module.Component(), Operations: []domain.Operation{{
		Kind: domain.OperationCreate, Resource: secret.Name, Summary: "create service hook " + secret.Name,
		Payload: serviceHookPayload{Project: "project", Secret: secret},
	}}}

	_, err := module.Apply(context.Background(), plan)
	if err == nil || strings.Contains(err.Error(), secret.Name) || strings.Contains(err.Error(), secret.Event) || strings.Contains(err.Error(), secret.URL) || strings.Contains(err.Error(), "password") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("apply error disclosed service hook secret: %v", err)
	}
	if errors.Is(err, service.writeErr) {
		t.Fatal("redacted error exposed the original secret-bearing error through unwrapping")
	}
}

func TestUnsupportedCapabilityIsTyped(t *testing.T) {
	module := NewOverview(UnsupportedOverviewService{})
	_, err := module.Plan(context.Background(), domain.ModuleInput{DesiredState: config.Config{General: config.GeneralConfig{TeamProjectName: "project"}, ProjectSettings: config.ProjectSettingsConfig{Overview: &config.OverviewConfig{}}}})
	var unsupported *azure.UnsupportedOperationError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected unsupported operation, got %v", err)
	}
}

type securityMemory struct {
	groups       []permissions.Group
	access       AccessSnapshot
	created      []string
	accessWrites [][]permissions.AccessChange
}

func (s *securityMemory) ListGroups(context.Context, string) ([]permissions.Group, error) {
	return append([]permissions.Group(nil), s.groups...), nil
}
func (s *securityMemory) CreateGroup(_ context.Context, _, name string) (permissions.Group, error) {
	group := permissions.Group{Name: name, Descriptor: "descriptor:" + name}
	s.groups = append(s.groups, group)
	s.created = append(s.created, name)
	return group, nil
}
func (s *securityMemory) ReadProjectAccess(context.Context, string) (AccessSnapshot, error) {
	return s.access, nil
}
func (s *securityMemory) SetProjectAccess(_ context.Context, _ string, changes []permissions.AccessChange) error {
	s.accessWrites = append(s.accessWrites, append([]permissions.AccessChange(nil), changes...))
	return nil
}
func (s *securityMemory) Invalidate(string) {}

func securityInput(create bool) domain.ModuleInput {
	return domain.ModuleInput{DesiredState: config.Config{
		General: config.GeneralConfig{
			TeamProjectName:   "project",
			GroupNameTemplate: "teamprojectname team role",
			GroupsAlias:       map[string]map[string]string{"Dev": {"Readers": "14"}},
		},
		ProjectSettings: config.ProjectSettingsConfig{Security: &config.SecurityConfig{
			CreateGroup: create,
			Permissions: config.AccessAssignments{
				"View": {config.AccessAllow: {"14"}},
			},
		}},
	}}
}

func TestSecurityNoOpPreservesExistingState(t *testing.T) {
	service := &securityMemory{
		groups: []permissions.Group{{Name: "project Dev Readers", Descriptor: "group-14"}},
		access: AccessSnapshot{
			Bits:   map[config.PermissionName]permissions.AccessBit{"View": 1},
			Values: map[string]map[permissions.AccessBit]config.AccessValue{"group-14": {1: config.AccessAllow}},
		},
	}
	plan, err := NewSecurity(service).Plan(context.Background(), securityInput(true))
	if err != nil || len(plan.Operations) != 0 {
		t.Fatalf("equal security state plan = %#v, %v", plan, err)
	}
}

func TestSecurityCreatesGroupBeforeApplyingPermissions(t *testing.T) {
	service := &securityMemory{access: AccessSnapshot{
		Bits:   map[config.PermissionName]permissions.AccessBit{"View": 1},
		Values: map[string]map[permissions.AccessBit]config.AccessValue{},
	}}
	module := NewSecurity(service)
	plan, err := module.Plan(context.Background(), securityInput(true))
	if err != nil || len(plan.Operations) != 2 {
		t.Fatalf("changed security state plan = %#v, %v", plan, err)
	}
	result, err := module.Apply(context.Background(), plan)
	if err != nil || len(result.Changes) != 2 || len(service.created) != 1 || len(service.accessWrites) != 1 {
		t.Fatalf("apply = %#v, created %#v, writes %#v, %v", result, service.created, service.accessWrites, err)
	}
	if got := service.accessWrites[0][0].Principal.Descriptor; !strings.HasPrefix(got, "descriptor:") {
		t.Fatalf("permission used unresolved descriptor %q", got)
	}
}
