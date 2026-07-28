package projectsettings

import (
	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
	"context"
	"fmt"
)

type agentPoolsModule struct {
	service   AgentPoolService
	directory permissions.GroupDirectory
}
type agentPoolPayload struct {
	Project, Pool string
	Changes       []permissions.RoleChange
}

func NewAgentPools(service AgentPoolService, directory permissions.GroupDirectory) domain.Module {
	return &agentPoolsModule{service, directory}
}
func (m *agentPoolsModule) ID() domain.ModuleID             { return AgentPoolsID }
func (m *agentPoolsModule) Component() domain.ComponentPath { return "projectsettings.agentpools" }
func (m *agentPoolsModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: m.ID(), Component: m.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.ProjectSettings.AgentPools == nil {
		return plan, moduleError(m, "read desired state", firstError(err, fmt.Errorf("agent pools configuration is required")))
	}
	if m.service == nil || m.directory == nil {
		return plan, moduleError(m, "read current state", fmt.Errorf("agent pool service and group directory are required"))
	}
	resolver, err := permissions.NewResolver(cfg.General, m.directory)
	if err != nil {
		return plan, moduleError(m, "resolve groups", err)
	}
	supported := map[config.Role]struct{}{config.RoleAdministrator: {}, config.RoleUser: {}, config.RoleReader: {}}
	for _, pool := range cfg.ProjectSettings.AgentPools.Permissions {
		principals := map[config.GroupSelector][]permissions.Principal{}
		for _, selectors := range pool.Permission {
			for _, selector := range selectors {
				if _, ok := principals[selector]; !ok {
					principals[selector], err = resolver.Resolve(ctx, []config.GroupSelector{selector})
					if err != nil {
						return plan, moduleError(m, "resolve groups", err)
					}
				}
			}
		}
		current, err := m.service.ReadAgentPoolRoles(ctx, cfg.General.TeamProjectName, pool.Name)
		if err != nil {
			return plan, moduleError(m, "read agent pool roles", err)
		}
		changes, err := permissions.PlanRoles(pool.Permission, principals, current, supported)
		if err != nil {
			return plan, moduleError(m, "plan agent pool roles", err)
		}
		if len(changes) > 0 {
			plan.Operations = append(plan.Operations, domain.Operation{Kind: domain.OperationPermission, Resource: pool.Name, Summary: fmt.Sprintf("set %d agent pool role assignment(s)", len(changes)), Payload: agentPoolPayload{cfg.General.TeamProjectName, pool.Name, changes}})
		}
	}
	return plan, nil
}
func (m *agentPoolsModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, op := range plan.Operations {
		p, ok := op.Payload.(agentPoolPayload)
		if !ok {
			return result, moduleError(m, "apply plan", fmt.Errorf("unsupported agent pool operation payload"))
		}
		if err := m.service.SetAgentPoolRoles(ctx, p.Project, p.Pool, p.Changes); err != nil {
			return result, moduleError(m, "set agent pool roles", err)
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: op.Kind, Resource: op.Resource, Summary: op.Summary})
	}
	return result, nil
}
