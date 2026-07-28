package detector

import (
	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
	"azops-cli/internal/modules/pipelines"
	"azops-cli/internal/modules/projectsettings"
)

// Dependencies contains the services used by registered module factories.
type Dependencies struct {
	GroupDirectory     permissions.GroupDirectory
	Security           projectsettings.SecurityService
	Repositories       projectsettings.RepositoryService
	Dashboards         projectsettings.DashboardService
	AgentPools         projectsettings.AgentPoolService
	Release            projectsettings.ReleaseService
	ServiceConnections projectsettings.ServiceConnectionService
	Test               projectsettings.TestService
	ServiceHook        projectsettings.ServiceHookService
	Settings           projectsettings.SettingsService
	Overview           projectsettings.OverviewService
	Environments       pipelines.EnvironmentService
	Library            pipelines.LibraryService
	TaskGroups         pipelines.TaskGroupService
	DeploymentGroup    pipelines.DeploymentGroupService
	PipelineAccess     pipelines.ScopedPermissionService
	ReleaseAccess      pipelines.ScopedPermissionService
}

// Factory creates a module for one detection run.
type Factory func() domain.Module

type registration struct {
	path    domain.ComponentPath
	stage   int
	present func(config.Config) bool
	factory Factory
}

// Registry contains one factory for every supported inner component.
type Registry struct {
	ordered []registration
	byPath  map[domain.ComponentPath]registration
}

// NewRegistry registers every supported module in stable stage order.
func NewRegistry(deps Dependencies) *Registry {
	items := []registration{
		{"projectsettings.security", 1, func(c config.Config) bool { return c.ProjectSettings.Security != nil }, func() domain.Module { return projectsettings.NewSecurity(deps.Security) }},
		{"projectsettings.repositories", 2, func(c config.Config) bool { return c.ProjectSettings.Repositories != nil }, func() domain.Module { return projectsettings.NewRepositories(deps.Repositories, deps.GroupDirectory) }},
		{"projectsettings.dashboards", 2, func(c config.Config) bool { return c.ProjectSettings.Dashboards != nil }, func() domain.Module { return projectsettings.NewDashboards(deps.Dashboards) }},
		{"projectsettings.agentpools", 2, func(c config.Config) bool { return c.ProjectSettings.AgentPools != nil }, func() domain.Module { return projectsettings.NewAgentPools(deps.AgentPools, deps.GroupDirectory) }},
		{"projectsettings.release", 2, func(c config.Config) bool { return c.ProjectSettings.Release != nil }, func() domain.Module { return projectsettings.NewRelease(deps.Release) }},
		{"projectsettings.serviceconnections", 2, func(c config.Config) bool { return c.ProjectSettings.ServiceConnections != nil }, func() domain.Module {
			return projectsettings.NewServiceConnections(deps.ServiceConnections, deps.GroupDirectory)
		}},
		{"projectsettings.test", 2, func(c config.Config) bool { return c.ProjectSettings.Test != nil }, func() domain.Module { return projectsettings.NewTest(deps.Test) }},
		{"pipelines.environments", 3, func(c config.Config) bool { return c.Pipelines.Environments != nil }, func() domain.Module { return pipelines.NewEnvironments(deps.Environments, deps.GroupDirectory) }},
		{"pipelines.library", 3, func(c config.Config) bool { return c.Pipelines.Library != nil }, func() domain.Module { return pipelines.NewLibrary(deps.Library, deps.GroupDirectory) }},
		{"pipelines.taskgroups", 3, func(c config.Config) bool { return c.Pipelines.TaskGroups != nil }, func() domain.Module { return pipelines.NewTaskGroups(deps.TaskGroups, deps.GroupDirectory) }},
		{"pipelines.deploymentgroup", 3, func(c config.Config) bool { return c.Pipelines.DeploymentGroup != nil }, func() domain.Module { return pipelines.NewDeploymentGroup(deps.DeploymentGroup, deps.GroupDirectory) }},
		{"pipelines.pipelines", 4, func(c config.Config) bool { return c.Pipelines.Pipelines != nil }, func() domain.Module { return pipelines.NewPipelines(deps.PipelineAccess, deps.GroupDirectory) }},
		{"pipelines.releases", 4, func(c config.Config) bool { return c.Pipelines.Releases != nil }, func() domain.Module { return pipelines.NewReleases(deps.ReleaseAccess, deps.GroupDirectory) }},
		{"projectsettings.servicehook", 5, func(c config.Config) bool { return c.ProjectSettings.ServiceHook != nil }, func() domain.Module { return projectsettings.NewServiceHook(deps.ServiceHook) }},
		{"projectsettings.settings", 6, func(c config.Config) bool { return c.ProjectSettings.Settings != nil }, func() domain.Module { return projectsettings.NewSettings(deps.Settings) }},
		{"projectsettings.overview", 6, func(c config.Config) bool { return c.ProjectSettings.Overview != nil }, func() domain.Module { return projectsettings.NewOverview(deps.Overview) }},
	}
	byPath := make(map[domain.ComponentPath]registration, len(items))
	for _, item := range items {
		byPath[item.path] = item
	}
	return &Registry{ordered: items, byPath: byPath}
}

// ModuleFor creates the registered module for path.
func (r *Registry) ModuleFor(path domain.ComponentPath) (domain.Module, bool) {
	if r == nil {
		return nil, false
	}
	item, ok := r.byPath[path]
	if !ok {
		return nil, false
	}
	return item.factory(), true
}
