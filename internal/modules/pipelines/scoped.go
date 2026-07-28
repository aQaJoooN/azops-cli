package pipelines

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

type scopedModule struct {
	id        domain.ModuleID
	component domain.ComponentPath
	label     string
	service   ScopedPermissionService
	directory permissions.GroupDirectory
}

type scopedAccessPayload struct {
	Project string
	Path    string
	Changes []permissions.AccessChange
}

func NewPipelines(service ScopedPermissionService, directory permissions.GroupDirectory) domain.Module {
	return &scopedModule{id: PipelinesID, component: "pipelines.pipelines", label: "pipeline", service: service, directory: directory}
}

func NewReleases(service ScopedPermissionService, directory permissions.GroupDirectory) domain.Module {
	return &scopedModule{id: ReleasesID, component: "pipelines.releases", label: "release", service: service, directory: directory}
}

func (module *scopedModule) ID() domain.ModuleID { return module.id }
func (module *scopedModule) Component() domain.ComponentPath { return module.component }

func (module *scopedModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: module.ID(), Component: module.Component()}
	cfg, err := desiredConfig(input)
	if err != nil {
		return plan, moduleError(module, "read desired state", err)
	}
	var desired *config.ScopedPermissionsConfig
	if module.id == PipelinesID {
		desired = cfg.Pipelines.Pipelines
	} else {
		desired = cfg.Pipelines.Releases
	}
	if desired == nil {
		return plan, moduleError(module, "read desired state", fmt.Errorf("%s configuration is required", module.label))
	}
	if module.service == nil || module.directory == nil {
		return plan, moduleError(module, "read current state", fmt.Errorf("%s service and group directory are required", module.label))
	}
	resolver, err := permissions.NewResolver(cfg.General, module.directory)
	if err != nil {
		return plan, moduleError(module, "configure group resolver", err)
	}
	entries := append([]config.ScopedPermissions(nil), desired.Permissions...)
	sort.SliceStable(entries, func(i, j int) bool {
		return canonicalPath(entries[i].Path) < canonicalPath(entries[j].Path)
	})
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		scope := canonicalPath(entry.Path)
		if _, exists := seen[scope]; exists {
			return plan, moduleError(module, "read desired state", fmt.Errorf("duplicate canonical path %q", scope))
		}
		seen[scope] = struct{}{}
		principals, err := resolveAccessPrincipalsWithResolver(ctx, entry.Permission, resolver)
		if err != nil {
			return plan, moduleError(module, "resolve groups for "+scope, err)
		}
		current, err := module.service.ReadScopedAccess(ctx, cfg.General.TeamProjectName, scope)
		if err != nil {
			return plan, moduleError(module, "read "+module.label+" permissions for "+scope, err)
		}
		changes, err := permissions.PlanAccess(entry.Permission, current.Bits, principals, current.Values)
		if err != nil {
			return plan, moduleError(module, "plan "+module.label+" permissions for "+scope, err)
		}
		if len(changes) > 0 {
			plan.Operations = append(plan.Operations, domain.Operation{
				Kind: domain.OperationPermission, Resource: scope,
				Summary: fmt.Sprintf("set %d %s permission assignment(s) at %s", len(changes), module.label, scope),
				Payload: scopedAccessPayload{Project: cfg.General.TeamProjectName, Path: scope, Changes: changes},
			})
		}
	}
	return plan, nil
}

func (module *scopedModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, operation := range plan.Operations {
		payload, ok := operation.Payload.(scopedAccessPayload)
		if !ok {
			return result, moduleError(module, "apply plan", fmt.Errorf("unsupported scoped permission operation payload"))
		}
		if err := module.service.SetScopedAccess(ctx, payload.Project, payload.Path, payload.Changes); err != nil {
			return result, moduleError(module, "set "+module.label+" permissions for "+payload.Path, err)
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary})
	}
	return result, nil
}

func canonicalPath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || strings.EqualFold(value, "root") || value == "/" {
		return "/"
	}
	cleaned := path.Clean("/" + strings.Trim(value, "/"))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}
