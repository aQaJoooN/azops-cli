package projectsettings

import (
	"fmt"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
)

const (
	SecurityID           domain.ModuleID = "projectSettings_security"
	RepositoriesID       domain.ModuleID = "projectSettings_repositories"
	DashboardsID         domain.ModuleID = "projectSettings_dashboards"
	AgentPoolsID         domain.ModuleID = "projectSettings_agentpools"
	ReleaseID            domain.ModuleID = "projectSettings_release"
	ServiceConnectionsID domain.ModuleID = "projectSettings_serviceconnections"
	TestID               domain.ModuleID = "projectSettings_test"
	ServiceHookID        domain.ModuleID = "projectSettings_servicehook"
	SettingsID           domain.ModuleID = "projectSettings_settings"
	OverviewID           domain.ModuleID = "projectSettings_overview"
)

func desiredConfig(input domain.ModuleInput) (config.Config, error) {
	switch value := input.DesiredState.(type) {
	case config.Config:
		return value, nil
	case *config.Config:
		if value != nil {
			return *value, nil
		}
	}
	return config.Config{}, fmt.Errorf("desired state must be config.Config")
}

func secretConfig(input domain.ModuleInput) config.Secrets {
	switch value := input.SecretState.(type) {
	case config.Secrets:
		return value
	case *config.Secrets:
		if value != nil {
			return *value
		}
	}
	return config.Secrets{}
}
