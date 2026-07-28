package projectsettings

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type securityModule struct{ service SecurityService }

type createGroupPayload struct{ Name string }
type accessPayload struct {
	Project string
	Changes []permissions.AccessChange
}

func NewSecurity(service SecurityService) domain.Module { return &securityModule{service: service} }
func (module *securityModule) ID() domain.ModuleID      { return SecurityID }
func (module *securityModule) Component() domain.ComponentPath {
	return "projectsettings.security"
}

func (module *securityModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: module.ID(), Component: module.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.ProjectSettings.Security == nil {
		return plan, moduleError(module, "read desired state", firstError(err, fmt.Errorf("security configuration is required")))
	}
	if module.service == nil {
		return plan, moduleError(module, "read current state", fmt.Errorf("security service is required"))
	}
	groups, err := module.service.ListGroups(ctx)
	if err != nil {
		return plan, moduleError(module, "list groups", err)
	}
	operations, principals, err := module.planGroups(cfg.General, cfg.ProjectSettings.Security.CreateGroup, groups)
	if err != nil {
		return plan, moduleError(module, "plan groups", err)
	}
	plan.Operations = append(plan.Operations, operations...)
	if len(cfg.ProjectSettings.Security.Permissions) == 0 {
		return plan, nil
	}
	snapshot, err := module.service.ReadProjectAccess(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(module, "read project permissions", err)
	}
	changes, err := permissions.PlanAccess(cfg.ProjectSettings.Security.Permissions, snapshot.Bits, principals, snapshot.Values)
	if err != nil {
		return plan, moduleError(module, "plan project permissions", err)
	}
	if len(changes) > 0 {
		plan.Operations = append(plan.Operations, accessOperation(cfg.General.TeamProjectName, changes))
	}
	return plan, nil
}

func (module *securityModule) planGroups(general config.GeneralConfig, create bool, current []permissions.Group) ([]domain.Operation, map[config.GroupSelector][]permissions.Principal, error) {
	byName := make(map[string]permissions.Group, len(current))
	for _, group := range current {
		if strings.TrimSpace(group.Name) == "" || strings.TrimSpace(group.Descriptor) == "" {
			return nil, nil, fmt.Errorf("Azure DevOps group contains an empty name or descriptor")
		}
		if previous, exists := byName[group.Name]; exists && previous.Descriptor != group.Descriptor {
			return nil, nil, fmt.Errorf("Azure DevOps group name %q resolves to multiple descriptors", group.Name)
		}
		byName[group.Name] = group
	}
	principals := make(map[config.GroupSelector][]permissions.Principal)
	operations := make([]domain.Operation, 0)
	all := make(map[string]permissions.Principal)
	teams := make([]string, 0, len(general.GroupsAlias))
	for team := range general.GroupsAlias {
		teams = append(teams, team)
	}
	sort.Strings(teams)
	for _, team := range teams {
		roles := make([]string, 0, len(general.GroupsAlias[team]))
		for role := range general.GroupsAlias[team] {
			roles = append(roles, role)
		}
		sort.Strings(roles)
		for _, role := range roles {
			alias := config.GroupSelector(general.GroupsAlias[team][role])
			if strings.TrimSpace(string(alias)) == "" || alias == permissions.AllGroups {
				return nil, nil, fmt.Errorf("invalid group alias %q for %s/%s", alias, team, role)
			}
			if _, exists := principals[alias]; exists {
				return nil, nil, fmt.Errorf("duplicate group alias %q", alias)
			}
			name, err := permissions.ExpandGroupName(general.GroupNameTemplate, general.TeamProjectName, team, role)
			if err != nil {
				return nil, nil, err
			}
			group, exists := byName[name]
			if !exists {
				if !create {
					return nil, nil, fmt.Errorf("group alias %q resolves to missing Azure DevOps group %q", alias, name)
				}
				group = permissions.Group{Name: name, Descriptor: "pending:" + name}
				operations = append(operations, domain.Operation{Kind: domain.OperationCreate, Resource: name, Summary: "create project group " + name, Payload: createGroupPayload{Name: name}})
			}
			principal := permissions.Principal{Alias: alias, Name: name, Descriptor: group.Descriptor}
			principals[alias] = []permissions.Principal{principal}
			all[group.Descriptor] = principal
		}
	}
	for _, group := range current {
		if strings.HasPrefix(group.Name, general.TeamProjectName) {
			all[group.Descriptor] = permissions.Principal{Alias: permissions.AllGroups, Name: group.Name, Descriptor: group.Descriptor}
		}
	}
	for _, principal := range all {
		principals[permissions.AllGroups] = append(principals[permissions.AllGroups], principal)
	}
	sort.Slice(principals[permissions.AllGroups], func(i, j int) bool {
		return principals[permissions.AllGroups][i].Name < principals[permissions.AllGroups][j].Name
	})
	return operations, principals, nil
}

func accessOperation(project string, changes []permissions.AccessChange) domain.Operation {
	summaries := make([]string, 0, len(changes))
	for _, change := range changes {
		summaries = append(summaries, fmt.Sprintf("%s:%s=%s", change.Principal.Name, change.Permission, change.Desired))
	}
	return domain.Operation{Kind: domain.OperationPermission, Resource: project, Summary: "set project permissions: " + fmt.Sprintf("%d assignment(s)", len(changes)), Payload: accessPayload{Project: project, Changes: changes}}
}

func (module *securityModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	if plan.Module != module.ID() || plan.Component != module.Component() {
		return result, moduleError(module, "apply plan", fmt.Errorf("plan belongs to %s", plan.Module))
	}
	created := make(map[string]permissions.Group)
	for _, operation := range plan.Operations {
		switch payload := operation.Payload.(type) {
		case createGroupPayload:
			group, err := module.service.CreateGroup(ctx, payload.Name)
			if err != nil {
				return result, moduleError(module, "create group "+payload.Name, err)
			}
			created["pending:"+payload.Name] = group
		case accessPayload:
			changes := append([]permissions.AccessChange(nil), payload.Changes...)
			for index := range changes {
				if group, exists := created[changes[index].Principal.Descriptor]; exists {
					changes[index].Principal.Descriptor = group.Descriptor
				}
			}
			if err := module.service.SetProjectAccess(ctx, payload.Project, changes); err != nil {
				return result, moduleError(module, "set project permissions", err)
			}
		default:
			return result, moduleError(module, "apply plan", fmt.Errorf("unsupported security operation payload"))
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary})
	}
	return result, nil
}

func moduleError(module domain.Module, operation string, err error) error {
	return &domain.ModuleError{Module: module.ID(), Component: module.Component(), Operation: operation, Err: err}
}

func firstError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}
