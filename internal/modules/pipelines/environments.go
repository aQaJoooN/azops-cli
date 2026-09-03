package pipelines

import (
	"context"
	"fmt"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type environmentsModule struct {
	service   EnvironmentService
	directory permissions.GroupDirectory
}

type environmentRolesPayload struct {
	Project string
	Changes []permissions.RoleChange
}

func NewEnvironments(service EnvironmentService, directory permissions.GroupDirectory) domain.Module {
	return &environmentsModule{service: service, directory: directory}
}

func (module *environmentsModule) ID() domain.ModuleID { return EnvironmentsID }
func (module *environmentsModule) Component() domain.ComponentPath {
	return "pipelines.environments"
}

func (module *environmentsModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: module.ID(), Component: module.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.Pipelines.Environments == nil {
		return plan, moduleError(module, "read desired state", firstError(err, fmt.Errorf("environments configuration is required")))
	}
	if module.service == nil || module.directory == nil {
		return plan, moduleError(module, "read current state", fmt.Errorf("environment service and group directory are required"))
	}
	principals, err := resolveRolePrincipals(ctx, cfg.General, cfg.Pipelines.Environments.Permissions, module.directory)
	if err != nil {
		return plan, moduleError(module, "resolve groups", err)
	}
	current, err := module.service.ReadEnvironmentRoles(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(module, "read environment roles", err)
	}
	supported := pipelineRoles()
	changes, err := permissions.PlanRoles(cfg.Pipelines.Environments.Permissions, principals, current, supported)
	if err != nil {
		return plan, moduleError(module, "plan environment roles", err)
	}
	if len(changes) > 0 {
		plan.Operations = append(plan.Operations, domain.Operation{
			Kind: domain.OperationPermission, Resource: "environments",
			Summary: fmt.Sprintf("set %d environment role assignment(s)", len(changes)),
			Payload: environmentRolesPayload{Project: cfg.General.TeamProjectName, Changes: changes},
		})
	}
	return plan, nil
}

func (module *environmentsModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, operation := range plan.Operations {
		payload, ok := operation.Payload.(environmentRolesPayload)
		if !ok {
			return result, moduleError(module, "apply plan", fmt.Errorf("unsupported environment operation payload"))
		}
		if err := module.service.SetEnvironmentRoles(ctx, payload.Project, payload.Changes); err != nil {
			return result, moduleError(module, "set environment roles", err)
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary})
	}
	return result, nil
}

func resolveRolePrincipals(ctx context.Context, general config.GeneralConfig, assignments config.RoleAssignments, directory permissions.GroupDirectory) (map[config.GroupSelector][]permissions.Principal, error) {
	resolver, err := permissions.NewResolver(general, directory)
	if err != nil {
		return nil, err
	}
	principals := make(map[config.GroupSelector][]permissions.Principal)
	for _, selectors := range assignments {
		for _, selector := range selectors {
			if _, exists := principals[selector]; exists {
				continue
			}
			principals[selector], err = resolver.Resolve(ctx, []config.GroupSelector{selector})
			if err != nil {
				return nil, err
			}
		}
	}
	return principals, nil
}

func pipelineRoles() map[config.Role]struct{} {
	return map[config.Role]struct{}{
		config.RoleAdministrator: {}, config.RoleCreator: {}, config.RoleUser: {}, config.RoleReader: {},
	}
}

