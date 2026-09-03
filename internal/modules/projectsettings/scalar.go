package projectsettings

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/domain"
)

type scalarKind uint8

const (
	scalarRelease scalarKind = iota
	scalarTest
	scalarSettings
	scalarOverview
)

type scalarModule struct {
	id        domain.ModuleID
	component domain.ComponentPath
	kind      scalarKind
	service   any
}
type scalarPayload struct {
	Project string
	Value   any
}

func NewRelease(service ReleaseService) domain.Module {
	return &scalarModule{ReleaseID, "projectsettings.release", scalarRelease, service}
}
func NewTest(service TestService) domain.Module {
	return &scalarModule{TestID, "projectsettings.test", scalarTest, service}
}
func NewSettings(service SettingsService) domain.Module {
	return &scalarModule{SettingsID, "projectsettings.settings", scalarSettings, service}
}
func NewOverview(service OverviewService) domain.Module {
	return &scalarModule{OverviewID, "projectsettings.overview", scalarOverview, service}
}
func (m *scalarModule) ID() domain.ModuleID             { return m.id }
func (m *scalarModule) Component() domain.ComponentPath { return m.component }
func (m *scalarModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: m.id, Component: m.component}
	cfg, err := desiredConfig(input)
	if err != nil {
		return plan, moduleError(m, "read desired state", err)
	}
	var current, desired any
	switch m.kind {
	case scalarRelease:
		if cfg.ProjectSettings.Release == nil {
			return plan, moduleError(m, "read desired state", fmt.Errorf("release configuration is required"))
		}
		service, ok := m.service.(ReleaseService)
		if !ok || service == nil {
			return plan, moduleError(m, "read current state", fmt.Errorf("release service is required"))
		}
		desired = *cfg.ProjectSettings.Release
		current, err = service.ReadReleaseRetention(ctx, cfg.General.TeamProjectName)
	case scalarTest:
		if cfg.ProjectSettings.Test == nil {
			return plan, moduleError(m, "read desired state", fmt.Errorf("test configuration is required"))
		}
		service, ok := m.service.(TestService)
		if !ok || service == nil {
			return plan, moduleError(m, "read current state", fmt.Errorf("test service is required"))
		}
		desired = *cfg.ProjectSettings.Test
		current, err = service.ReadTestRetention(ctx, cfg.General.TeamProjectName)
	case scalarSettings:
		if cfg.ProjectSettings.Settings == nil {
			return plan, moduleError(m, "read desired state", fmt.Errorf("settings configuration is required"))
		}
		service, ok := m.service.(SettingsService)
		if !ok || service == nil {
			return plan, moduleError(m, "read current state", fmt.Errorf("settings service is required"))
		}
		desired = *cfg.ProjectSettings.Settings
		var raw config.PipelineSettingsConfig
		raw, err = service.ReadPipelineSettings(ctx, cfg.General.TeamProjectName)
		if err == nil {
			// Retention fields (Days_to_keep_*) are applied best-effort via build/retention.
			// A collection-level maximum policy may override project values after writing,
			// so we exclude them from the idempotency check to avoid a permanent diff loop.
			// They are still written every time a general-settings change is detected,
			// and on first apply when general settings also differ.
			rawCopy := raw
			rawCopy.RetentionPolicy = cfg.ProjectSettings.Settings.RetentionPolicy
			rawCopy.RetentionPolicy.RecentRunCount = 0
			desiredCopy := *cfg.ProjectSettings.Settings
			desiredCopy.RetentionPolicy.RecentRunCount = 0
			current = rawCopy
			desired = desiredCopy
		}
	case scalarOverview:
		if cfg.ProjectSettings.Overview == nil {
			return plan, moduleError(m, "read desired state", fmt.Errorf("overview configuration is required"))
		}
		service, ok := m.service.(OverviewService)
		if !ok || service == nil {
			return plan, moduleError(m, "read current state", fmt.Errorf("overview service is required"))
		}
		desired = *cfg.ProjectSettings.Overview
		current, err = service.ReadOverview(ctx, cfg.General.TeamProjectName)
	default:
		return plan, moduleError(m, "read desired state", fmt.Errorf("unsupported scalar module kind"))
	}
	if err != nil {
		// For overview, propagate unsupported errors so callers can detect them as typed errors.
		// For all other scalar modules (release, test, settings), skip gracefully — Azure DevOps
		// Server may not expose a public API for these, and skipping is the correct fallback.
		var unsupported *azure.UnsupportedOperationError
		if errors.As(err, &unsupported) && m.kind != scalarOverview {
			plan.SkipReason = unsupported.Error()
			return plan, nil
		}
		return plan, moduleError(m, "read current state", err)
	}
	if !reflect.DeepEqual(current, desired) {
		plan.Operations = []domain.Operation{{Kind: domain.OperationUpdate, Resource: string(m.component), Summary: "update " + string(m.component), Payload: scalarPayload{cfg.General.TeamProjectName, desired}}}
	}
	return plan, nil
}
func (m *scalarModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, op := range plan.Operations {
		p, ok := op.Payload.(scalarPayload)
		if !ok {
			return result, moduleError(m, "apply plan", fmt.Errorf("unsupported settings operation payload"))
		}
		var err error
		switch m.kind {
		case scalarRelease:
			service, serviceOK := m.service.(ReleaseService)
			value, valueOK := p.Value.(config.ReleaseRetentionConfig)
			if !serviceOK || service == nil || !valueOK {
				return result, moduleError(m, "apply plan", fmt.Errorf("invalid release service or payload"))
			}
			err = service.SetReleaseRetention(ctx, p.Project, value)
		case scalarTest:
			service, serviceOK := m.service.(TestService)
			value, valueOK := p.Value.(config.TestRetentionConfig)
			if !serviceOK || service == nil || !valueOK {
				return result, moduleError(m, "apply plan", fmt.Errorf("invalid test service or payload"))
			}
			err = service.SetTestRetention(ctx, p.Project, value)
		case scalarSettings:
			service, serviceOK := m.service.(SettingsService)
			value, valueOK := p.Value.(config.PipelineSettingsConfig)
			if !serviceOK || service == nil || !valueOK {
				return result, moduleError(m, "apply plan", fmt.Errorf("invalid settings service or payload"))
			}
			err = service.SetPipelineSettings(ctx, p.Project, value)
		case scalarOverview:
			service, serviceOK := m.service.(OverviewService)
			value, valueOK := p.Value.(config.OverviewConfig)
			if !serviceOK || service == nil || !valueOK {
				return result, moduleError(m, "apply plan", fmt.Errorf("invalid overview service or payload"))
			}
			err = service.SetOverview(ctx, p.Project, value)
		default:
			return result, moduleError(m, "apply plan", fmt.Errorf("unsupported scalar module kind"))
		}
		if err != nil {
			return result, moduleError(m, "update current state", err)
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: op.Kind, Resource: op.Resource, Summary: op.Summary})
	}
	return result, nil
}
