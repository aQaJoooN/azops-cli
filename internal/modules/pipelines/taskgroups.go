package pipelines

import (
	"context"
	"fmt"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type taskGroupsModule struct {
	service   TaskGroupService
	directory permissions.GroupDirectory
}

type taskGroupAccessPayload struct {
	Project string
	Changes []permissions.AccessChange
}

func NewTaskGroups(service TaskGroupService, directory permissions.GroupDirectory) domain.Module {
	return &taskGroupsModule{service: service, directory: directory}
}

func (module *taskGroupsModule) ID() domain.ModuleID { return TaskGroupsID }
func (module *taskGroupsModule) Component() domain.ComponentPath { return "pipelines.taskgroups" }

func (module *taskGroupsModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: module.ID(), Component: module.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.Pipelines.TaskGroups == nil {
		return plan, moduleError(module, "read desired state", firstError(err, fmt.Errorf("task groups configuration is required")))
	}
	if module.service == nil || module.directory == nil {
		return plan, moduleError(module, "read current state", fmt.Errorf("task group service and group directory are required"))
	}
	principals, err := resolveAccessPrincipals(ctx, cfg.General, cfg.Pipelines.TaskGroups.Permissions, module.directory)
	if err != nil {
		return plan, moduleError(module, "resolve groups", err)
	}
	current, err := module.service.ReadTaskGroupAccess(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(module, "read task group permissions", err)
	}
	changes, err := permissions.PlanAccess(cfg.Pipelines.TaskGroups.Permissions, current.Bits, principals, current.Values)
	if err != nil {
		return plan, moduleError(module, "plan task group permissions", err)
	}
	if len(changes) > 0 {
		plan.Operations = append(plan.Operations, domain.Operation{
			Kind: domain.OperationPermission, Resource: "task groups",
			Summary: fmt.Sprintf("set %d task group permission assignment(s)", len(changes)),
			Payload: taskGroupAccessPayload{Project: cfg.General.TeamProjectName, Changes: changes},
		})
	}
	return plan, nil
}

func (module *taskGroupsModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, operation := range plan.Operations {
		payload, ok := operation.Payload.(taskGroupAccessPayload)
		if !ok {
			return result, moduleError(module, "apply plan", fmt.Errorf("unsupported task group operation payload"))
		}
		if err := module.service.SetTaskGroupAccess(ctx, payload.Project, payload.Changes); err != nil {
			return result, moduleError(module, "set task group permissions", err)
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary})
	}
	return result, nil
}

func resolveAccessPrincipals(ctx context.Context, general config.GeneralConfig, assignments config.AccessAssignments, directory permissions.GroupDirectory) (map[config.GroupSelector][]permissions.Principal, error) {
	resolver, err := permissions.NewResolver(general, directory)
	if err != nil {
		return nil, err
	}
	return resolveAccessPrincipalsWithResolver(ctx, assignments, resolver)
}

func resolveAccessPrincipalsWithResolver(ctx context.Context, assignments config.AccessAssignments, resolver *permissions.Resolver) (map[config.GroupSelector][]permissions.Principal, error) {
	principals := make(map[config.GroupSelector][]permissions.Principal)
	for _, byAccess := range assignments {
		for _, selectors := range byAccess {
			for _, selector := range selectors {
				if _, exists := principals[selector]; exists {
					continue
				}
				resolved, err := resolver.Resolve(ctx, []config.GroupSelector{selector})
				if err != nil {
					return nil, err
				}
				principals[selector] = resolved
			}
		}
	}
	return principals, nil
}
