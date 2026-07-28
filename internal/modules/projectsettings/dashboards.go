package projectsettings

import (
	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"context"
	"fmt"
)

type dashboardsModule struct{ service DashboardService }
type dashboardPayload struct {
	Project  string
	Security config.DashboardSecurity
}

func NewDashboards(service DashboardService) domain.Module  { return &dashboardsModule{service} }
func (m *dashboardsModule) ID() domain.ModuleID             { return DashboardsID }
func (m *dashboardsModule) Component() domain.ComponentPath { return "projectsettings.dashboards" }
func (m *dashboardsModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: m.ID(), Component: m.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.ProjectSettings.Dashboards == nil {
		return plan, moduleError(m, "read desired state", firstError(err, fmt.Errorf("dashboards configuration is required")))
	}
	if m.service == nil {
		return plan, moduleError(m, "read current state", fmt.Errorf("dashboard service is required"))
	}
	current, err := m.service.ReadDashboardSecurity(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(m, "read dashboard security", err)
	}
	desired := cfg.ProjectSettings.Dashboards.Security
	if current != desired {
		plan.Operations = []domain.Operation{{Kind: domain.OperationPermission, Resource: "dashboards", Summary: "update dashboard security", Payload: dashboardPayload{cfg.General.TeamProjectName, desired}}}
	}
	return plan, nil
}
func (m *dashboardsModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, op := range plan.Operations {
		p, ok := op.Payload.(dashboardPayload)
		if !ok {
			return result, moduleError(m, "apply plan", fmt.Errorf("unsupported dashboard operation payload"))
		}
		if err := m.service.SetDashboardSecurity(ctx, p.Project, p.Security); err != nil {
			return result, moduleError(m, "set dashboard security", err)
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: op.Kind, Resource: op.Resource, Summary: op.Summary})
	}
	return result, nil
}
