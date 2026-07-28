package pipelines

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type libraryModule struct {
	service   LibraryService
	directory permissions.GroupDirectory
}

type variableGroupPayload struct {
	Project string
	Secret  config.VariableGroupSecret
}

type libraryRolesPayload struct {
	Project string
	Changes []permissions.RoleChange
}

func NewLibrary(service LibraryService, directory permissions.GroupDirectory) domain.Module {
	return &libraryModule{service: service, directory: directory}
}

func (module *libraryModule) ID() domain.ModuleID { return LibraryID }
func (module *libraryModule) Component() domain.ComponentPath { return "pipelines.library" }

func (module *libraryModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: module.ID(), Component: module.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.Pipelines.Library == nil {
		return plan, moduleError(module, "read desired state", firstError(err, fmt.Errorf("library configuration is required")))
	}
	if module.service == nil || module.directory == nil {
		return plan, moduleError(module, "read current state", fmt.Errorf("library service and group directory are required"))
	}
	currentGroups, err := module.service.ListVariableGroups(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(module, "list variable groups", err)
	}
	currentByName := make(map[string]VariableGroup, len(currentGroups))
	for _, group := range currentGroups {
		currentByName[group.Name] = group
	}
	secretByName := make(map[string]config.VariableGroupSecret)
	for _, secret := range secretConfig(input).Pipelines.Library {
		secretByName[secret.Name] = secret
	}
	names := append([]string(nil), cfg.Pipelines.Library.Create...)
	sort.Strings(names)
	for _, name := range names {
		secret, exists := secretByName[name]
		if !exists {
			return plan, moduleError(module, "match variable group secret", fmt.Errorf("missing same-name secret entry for %q", name))
		}
		desiredVariables := variableMap(secret.Variables)
		current, exists := currentByName[name]
		if exists && reflect.DeepEqual(current.Variables, desiredVariables) {
			continue
		}
		kind := domain.OperationCreate
		if exists {
			kind = domain.OperationUpdate
		}
		plan.Operations = append(plan.Operations, domain.Operation{
			Kind: kind, Resource: name, Summary: string(kind) + " variable group " + name,
			Payload: variableGroupPayload{Project: cfg.General.TeamProjectName, Secret: secret},
		})
	}
	principals, err := resolveRolePrincipals(ctx, cfg.General, cfg.Pipelines.Library.Permissions, module.directory)
	if err != nil {
		return plan, moduleError(module, "resolve groups", err)
	}
	currentRoles, err := module.service.ReadLibraryRoles(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(module, "read library roles", err)
	}
	changes, err := permissions.PlanRoles(cfg.Pipelines.Library.Permissions, principals, currentRoles, pipelineRoles())
	if err != nil {
		return plan, moduleError(module, "plan library roles", err)
	}
	if len(changes) > 0 {
		plan.Operations = append(plan.Operations, domain.Operation{
			Kind: domain.OperationPermission, Resource: "library",
			Summary: fmt.Sprintf("set %d library role assignment(s)", len(changes)),
			Payload: libraryRolesPayload{Project: cfg.General.TeamProjectName, Changes: changes},
		})
	}
	return plan, nil
}

func (module *libraryModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, operation := range plan.Operations {
		switch payload := operation.Payload.(type) {
		case variableGroupPayload:
			if err := module.service.UpsertVariableGroup(ctx, payload.Project, payload.Secret); err != nil {
				return result, moduleError(module, "upsert variable group "+operation.Resource, err)
			}
		case libraryRolesPayload:
			if err := module.service.SetLibraryRoles(ctx, payload.Project, payload.Changes); err != nil {
				return result, moduleError(module, "set library roles", err)
			}
		default:
			return result, moduleError(module, "apply plan", fmt.Errorf("unsupported library operation payload"))
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary})
	}
	return result, nil
}

func variableMap(variables []config.SecretVariable) map[string]string {
	values := make(map[string]string, len(variables))
	for _, variable := range variables {
		values[variable.Name] = variable.Value
	}
	return values
}
