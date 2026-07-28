package projectsettings

import (
	"context"
	"fmt"
	"sort"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type serviceConnectionsModule struct {
	service   ServiceConnectionService
	directory permissions.GroupDirectory
}
type serviceConnectionPayload struct {
	Project string
	Secret  config.ServiceConnectionSecret
}
type serviceConnectionRolesPayload struct {
	Project string
	Changes []permissions.RoleChange
}

func NewServiceConnections(service ServiceConnectionService, directory permissions.GroupDirectory) domain.Module {
	return &serviceConnectionsModule{service: service, directory: directory}
}
func (m *serviceConnectionsModule) ID() domain.ModuleID { return ServiceConnectionsID }
func (m *serviceConnectionsModule) Component() domain.ComponentPath {
	return "projectsettings.serviceconnections"
}
func (m *serviceConnectionsModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: m.ID(), Component: m.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.ProjectSettings.ServiceConnections == nil {
		return plan, moduleError(m, "read desired state", firstError(err, fmt.Errorf("service connections configuration is required")))
	}
	if m.service == nil {
		return plan, moduleError(m, "read current state", fmt.Errorf("service connection service is required"))
	}
	if len(cfg.ProjectSettings.ServiceConnections.Permissions) > 0 && m.directory == nil {
		return plan, moduleError(m, "read current state", fmt.Errorf("group directory is required for service connection permissions"))
	}
	current, err := m.service.ListServiceConnections(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(m, "list service connections", err)
	}
	byCurrent := map[string]ServiceConnection{}
	for _, item := range current {
		byCurrent[item.Name] = item
	}
	secrets := secretConfig(input)
	bySecret := map[string]config.ServiceConnectionSecret{}
	for _, secret := range secrets.ProjectSettings.ServiceConnections {
		bySecret[secret.Name] = secret
	}
	names := append([]string(nil), cfg.ProjectSettings.ServiceConnections.Create...)
	sort.Strings(names)
	for _, name := range names {
		secret, ok := bySecret[name]
		if !ok {
			return plan, moduleError(m, "match service connection secret", fmt.Errorf("missing same-name secret entry for %q", name))
		}
		existing, exists := byCurrent[name]
		desired := ServiceConnection{Name: secret.Name, Type: secret.Type, URL: secret.URL, Auth: secret.Auth, GrantAccess: secret.GrantAccess}
		if !exists || existing != desired {
			kind := domain.OperationCreate
			if exists {
				kind = domain.OperationUpdate
			}
			plan.Operations = append(plan.Operations, domain.Operation{Kind: kind, Resource: name, Summary: string(kind) + " service connection " + name, Payload: serviceConnectionPayload{cfg.General.TeamProjectName, secret}})
		}
	}
	if len(cfg.ProjectSettings.ServiceConnections.Permissions) > 0 {
		resolver, err := permissions.NewResolver(cfg.General, m.directory)
		if err != nil {
			return plan, moduleError(m, "resolve groups", err)
		}
		principals := make(map[config.GroupSelector][]permissions.Principal)
		for _, selectors := range cfg.ProjectSettings.ServiceConnections.Permissions {
			for _, selector := range selectors {
				if _, exists := principals[selector]; !exists {
					principals[selector], err = resolver.Resolve(ctx, []config.GroupSelector{selector})
					if err != nil {
						return plan, moduleError(m, "resolve groups", err)
					}
				}
			}
		}
		currentRoles, err := m.service.ReadServiceConnectionRoles(ctx, cfg.General.TeamProjectName)
		if err != nil {
			return plan, moduleError(m, "read service connection roles", err)
		}
		supported := map[config.Role]struct{}{config.RoleCreator: {}, config.RoleUser: {}, config.RoleReader: {}}
		changes, err := permissions.PlanRoles(cfg.ProjectSettings.ServiceConnections.Permissions, principals, currentRoles, supported)
		if err != nil {
			return plan, moduleError(m, "plan service connection roles", err)
		}
		if len(changes) > 0 {
			plan.Operations = append(plan.Operations, domain.Operation{
				Kind: domain.OperationPermission, Resource: "service connections",
				Summary: fmt.Sprintf("set %d service connection role assignment(s)", len(changes)),
				Payload: serviceConnectionRolesPayload{Project: cfg.General.TeamProjectName, Changes: changes},
			})
		}
	}
	return plan, nil
}
func (m *serviceConnectionsModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, op := range plan.Operations {
		switch p := op.Payload.(type) {
		case serviceConnectionPayload:
			if err := m.service.UpsertServiceConnection(ctx, p.Project, p.Secret); err != nil {
				return result, moduleError(m, "upsert service connection "+op.Resource, err)
			}
		case serviceConnectionRolesPayload:
			if err := m.service.SetServiceConnectionRoles(ctx, p.Project, p.Changes); err != nil {
				return result, moduleError(m, "set service connection roles", err)
			}
		default:
			return result, moduleError(m, "apply plan", fmt.Errorf("unsupported service connection operation payload"))
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: op.Kind, Resource: op.Resource, Summary: op.Summary})
	}
	return result, nil
}
