package projectsettings

import (
	"context"
	"fmt"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type repositoriesModule struct {
	service   RepositoryService
	directory permissions.GroupDirectory
}
type repositoryPolicyPayload struct{ Project, MaximumFileSize string }
type repositoryAccessPayload struct {
	Project string
	Changes []permissions.AccessChange
}

func NewRepositories(service RepositoryService, directory permissions.GroupDirectory) domain.Module {
	return &repositoriesModule{service, directory}
}
func (m *repositoriesModule) ID() domain.ModuleID             { return RepositoriesID }
func (m *repositoriesModule) Component() domain.ComponentPath { return "projectsettings.repositories" }
func (m *repositoriesModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: m.ID(), Component: m.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.ProjectSettings.Repositories == nil {
		return plan, moduleError(m, "read desired state", firstError(err, fmt.Errorf("repositories configuration is required")))
	}
	if m.service == nil || m.directory == nil {
		return plan, moduleError(m, "read current state", fmt.Errorf("repository service and group directory are required"))
	}
	desired := cfg.ProjectSettings.Repositories
	state, err := m.service.ReadRepositoryState(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(m, "read repositories", err)
	}
	if state.MaximumFileSize != desired.Policies.MaximumFileSize {
		plan.Operations = append(plan.Operations, domain.Operation{Kind: domain.OperationUpdate, Resource: "repository policies", Summary: "set maximum file size to " + desired.Policies.MaximumFileSize, Payload: repositoryPolicyPayload{cfg.General.TeamProjectName, desired.Policies.MaximumFileSize}})
	}
	resolver, err := permissions.NewResolver(cfg.General, m.directory)
	if err != nil {
		return plan, moduleError(m, "resolve groups", err)
	}
	principals := map[config.GroupSelector][]permissions.Principal{}
	for _, selectors := range desired.Permissions {
		for _, groups := range selectors {
			for _, selector := range groups {
				if _, ok := principals[selector]; !ok {
					principals[selector], err = resolver.Resolve(ctx, []config.GroupSelector{selector})
					if err != nil {
						return plan, moduleError(m, "resolve groups", err)
					}
				}
			}
		}
	}
	changes, err := permissions.PlanAccess(desired.Permissions, state.Access.Bits, principals, state.Access.Values)
	if err != nil {
		return plan, moduleError(m, "plan repository permissions", err)
	}
	if len(changes) > 0 {
		plan.Operations = append(plan.Operations, domain.Operation{Kind: domain.OperationPermission, Resource: "repositories", Summary: fmt.Sprintf("set %d repository permission assignment(s)", len(changes)), Payload: repositoryAccessPayload{cfg.General.TeamProjectName, changes}})
	}
	return plan, nil
}
func (m *repositoriesModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, op := range plan.Operations {
		switch p := op.Payload.(type) {
		case repositoryPolicyPayload:
			if err := m.service.SetMaximumFileSize(ctx, p.Project, p.MaximumFileSize); err != nil {
				return result, moduleError(m, "set repository policy", err)
			}
		case repositoryAccessPayload:
			if err := m.service.SetRepositoryAccess(ctx, p.Project, p.Changes); err != nil {
				return result, moduleError(m, "set repository permissions", err)
			}
		default:
			return result, moduleError(m, "apply plan", fmt.Errorf("unsupported repository operation payload"))
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: op.Kind, Resource: op.Resource, Summary: op.Summary})
	}
	return result, nil
}
