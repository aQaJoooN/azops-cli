package pipelines

import (
	"context"
	"errors"
	"fmt"

	"azops-cli/internal/azure"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type deploymentGroupModule struct {
	service   DeploymentGroupService
	directory permissions.GroupDirectory
}

type deploymentGroupRolesPayload struct {
	Project string
	Changes []permissions.RoleChange
}

func NewDeploymentGroup(service DeploymentGroupService, directory permissions.GroupDirectory) domain.Module {
	return &deploymentGroupModule{service: service, directory: directory}
}

func (module *deploymentGroupModule) ID() domain.ModuleID { return DeploymentGroupID }
func (module *deploymentGroupModule) Component() domain.ComponentPath {
	return "pipelines.deploymentgroup"
}

func (module *deploymentGroupModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: module.ID(), Component: module.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.Pipelines.DeploymentGroup == nil {
		return plan, moduleError(module, "read desired state", firstError(err, fmt.Errorf("deployment group configuration is required")))
	}
	if module.service == nil || module.directory == nil {
		return plan, moduleError(module, "read current state", fmt.Errorf("deployment group service and group directory are required"))
	}
	principals, err := resolveRolePrincipals(ctx, cfg.General, cfg.Pipelines.DeploymentGroup.Permissions, module.directory)
	if err != nil {
		return plan, moduleError(module, "resolve groups", err)
	}
	current, err := module.service.ReadDeploymentGroupRoles(ctx, cfg.General.TeamProjectName)
	if err != nil {
		var unsupported *azure.UnsupportedOperationError
		if errors.As(err, &unsupported) {
			plan.SkipReason = unsupported.Error()
			return plan, nil
		}
		return plan, moduleError(module, "read deployment group roles", err)
	}
	changes, err := permissions.PlanRoles(cfg.Pipelines.DeploymentGroup.Permissions, principals, current, pipelineRoles())
	if err != nil {
		return plan, moduleError(module, "plan deployment group roles", err)
	}
	if len(changes) > 0 {
		plan.Operations = append(plan.Operations, domain.Operation{
			Kind: domain.OperationPermission, Resource: "deployment groups",
			Summary: fmt.Sprintf("set %d deployment group role assignment(s)", len(changes)),
			Payload: deploymentGroupRolesPayload{Project: cfg.General.TeamProjectName, Changes: changes},
		})
	}
	return plan, nil
}

func (module *deploymentGroupModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, operation := range plan.Operations {
		payload, ok := operation.Payload.(deploymentGroupRolesPayload)
		if !ok {
			return result, moduleError(module, "apply plan", fmt.Errorf("unsupported deployment group operation payload"))
		}
		if err := module.service.SetDeploymentGroupRoles(ctx, payload.Project, payload.Changes); err != nil {
			return result, moduleError(module, "set deployment group roles", err)
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary})
	}
	return result, nil
}
