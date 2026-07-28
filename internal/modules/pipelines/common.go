package pipelines

import (
	"fmt"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
)

const (
	EnvironmentsID    domain.ModuleID = "pipelines_environments"
	LibraryID         domain.ModuleID = "pipelines_library"
	TaskGroupsID      domain.ModuleID = "pipelines_taskgroups"
	DeploymentGroupID domain.ModuleID = "pipelines_deploymentgroup"
	PipelinesID       domain.ModuleID = "pipelines_pipelines"
	ReleasesID        domain.ModuleID = "pipelines_releases"
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

func moduleError(module domain.Module, operation string, err error) error {
	return &domain.ModuleError{Module: module.ID(), Component: module.Component(), Operation: operation, Err: err}
}

func firstError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}
