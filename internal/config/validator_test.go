package config

import (
	"errors"
	"strings"
	"testing"

	"azops-cli/internal/domain"
)

func TestValidateAggregatesDuplicatesAndPermissionConflicts(t *testing.T) {
	loaded := validLoadedInputs()
	loaded.Config.ProjectSettings.ServiceHook = &CreateConfig{Create: []string{"hook", "hook"}}
	loaded.Config.ProjectSettings.Security = &SecurityConfig{Permissions: AccessAssignments{
		"Read": {AccessAllow: {"all"}, AccessDeny: {"14"}},
	}}

	err := Validate(domain.Selection{Kind: domain.SelectionAll}, loaded)
	assertValidationContains(t, err, "config.yaml:projectsettings.servicehook.create[1]", "duplicate resource name")
	assertValidationContains(t, err, "config.yaml:projectsettings.security.permissions.Read", "conflicts with all selector")
}

func TestValidateRequiresSecretsOnlyForSelectedScope(t *testing.T) {
	loaded := validLoadedInputs()
	loaded.Config.ProjectSettings.ServiceHook = &CreateConfig{Create: []string{"hook"}}
	loaded.Config.Pipelines.Environments = &RolePermissionsConfig{}

	if err := Validate(domain.Selection{Kind: domain.SelectionComponent, Path: "pipelines.environments"}, loaded); err != nil {
		t.Fatalf("unselected secret-dependent component caused validation failure: %v", err)
	}
	err := Validate(domain.Selection{Kind: domain.SelectionComponent, Path: "projectsettings.servicehook"}, loaded)
	assertValidationContains(t, err, "secret.yaml:projectsettings.servicehook", "missing same-name secret entry")
}

func TestValidateSameNameSecretAndServiceConnectionCredentials(t *testing.T) {
	loaded := validLoadedInputs()
	loaded.Config.ProjectSettings.ServiceConnections = &ServiceConnectionsConfig{Create: []string{"registry"}}
	loaded.Secrets.ProjectSettings.ServiceConnections = []ServiceConnectionSecret{
		{Name: "registry", Type: "Docker Registry", URL: "https://registry.example", User: "user"},
		{Name: "registry", Type: "Docker Registry", URL: "https://registry.example", User: "user", Password: "password"},
	}

	err := Validate(domain.Selection{Kind: domain.SelectionComponent, Path: "projectsettings.serviceconnections"}, loaded)
	assertValidationContains(t, err, "secret.yaml:projectsettings.serviceconnections", "matches 2 entries")

	loaded.Secrets.ProjectSettings.ServiceConnections = loaded.Secrets.ProjectSettings.ServiceConnections[:1]
	err = Validate(domain.Selection{Kind: domain.SelectionComponent, Path: "projectsettings.serviceconnections"}, loaded)
	assertValidationContains(t, err, "secret.yaml:projectsettings.serviceconnections[0].password", "value is required")
}

func validLoadedInputs() LoadedInputs {
	return LoadedInputs{
		ConfigPath: "config.yaml",
		SecretPath: "secret.yaml",
		Config: Config{General: GeneralConfig{
			TeamProjectName: "project",
			GroupsAlias: map[string]map[string]string{"Dev": {"Readers": "14"}},
			GroupNameTemplate: "teamprojectname team role",
		}},
	}
}

func assertValidationContains(t *testing.T, err error, field, message string) {
	t.Helper()
	var validationErr *domain.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	for _, fieldErr := range validationErr.Errors {
		if fieldErr.Field == field && strings.Contains(fieldErr.Message, message) { return }
	}
	t.Fatalf("validation error missing %q with %q: %v", field, message, validationErr.Errors)
}
