package detector

import (
	"errors"
	"reflect"
	"testing"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
)

func fullConfig() config.Config {
	return config.Config{
		ProjectSettings: config.ProjectSettingsConfig{
			Overview: &config.OverviewConfig{}, Security: &config.SecurityConfig{},
			ServiceHook: &config.CreateConfig{}, Dashboards: &config.DashboardsConfig{},
			Repositories: &config.RepositoriesConfig{}, AgentPools: &config.AgentPoolsConfig{},
			Settings: &config.PipelineSettingsConfig{}, Release: &config.ReleaseRetentionConfig{},
			ServiceConnections: &config.ServiceConnectionsConfig{}, Test: &config.TestRetentionConfig{},
		},
		Pipelines: config.PipelinesConfig{
			Pipelines: &config.ScopedPermissionsConfig{}, Environments: &config.RolePermissionsConfig{},
			Library: &config.LibraryConfig{}, Releases: &config.ScopedPermissionsConfig{},
			TaskGroups: &config.AccessPermissionsConfig{}, DeploymentGroup: &config.RolePermissionsConfig{},
		},
	}
}

func TestRegistryMapsEveryComponentOnce(t *testing.T) {
	want := []struct {
		path  domain.ComponentPath
		id    domain.ModuleID
		stage int
	}{
		{"projectsettings.security", "projectSettings_security", 1},
		{"projectsettings.repositories", "projectSettings_repositories", 2},
		{"projectsettings.dashboards", "projectSettings_dashboards", 2},
		{"projectsettings.agentpools", "projectSettings_agentpools", 2},
		{"projectsettings.release", "projectSettings_release", 2},
		{"projectsettings.serviceconnections", "projectSettings_serviceconnections", 2},
		{"projectsettings.test", "projectSettings_test", 2},
		{"pipelines.environments", "pipelines_environments", 3},
		{"pipelines.library", "pipelines_library", 3},
		{"pipelines.taskgroups", "pipelines_taskgroups", 3},
		{"pipelines.deploymentgroup", "pipelines_deploymentgroup", 3},
		{"pipelines.pipelines", "pipelines_pipelines", 4},
		{"pipelines.releases", "pipelines_releases", 4},
		{"projectsettings.servicehook", "projectSettings_servicehook", 5},
		{"projectsettings.settings", "projectSettings_settings", 6},
		{"projectsettings.overview", "projectSettings_overview", 6},
	}

	registry := NewRegistry(Dependencies{})
	if len(registry.ordered) != len(want) || len(registry.byPath) != len(want) {
		t.Fatalf("registry sizes = %d, %d; want %d", len(registry.ordered), len(registry.byPath), len(want))
	}
	seenPaths := map[domain.ComponentPath]bool{}
	seenIDs := map[domain.ModuleID]bool{}
	for i, expected := range want {
		item := registry.ordered[i]
		module, ok := registry.ModuleFor(expected.path)
		if !ok {
			t.Errorf("ModuleFor(%q) was not found", expected.path)
			continue
		}
		if item.path != expected.path || item.stage != expected.stage || module.ID() != expected.id || module.Component() != expected.path {
			t.Errorf("registration %d = (%q, %q, stage %d); want (%q, %q, stage %d)", i, item.path, module.ID(), item.stage, expected.path, expected.id, expected.stage)
		}
		if seenPaths[module.Component()] || seenIDs[module.ID()] {
			t.Errorf("duplicate registration for component %q or module %q", module.Component(), module.ID())
		}
		seenPaths[module.Component()] = true
		seenIDs[module.ID()] = true
	}
}

func TestDetectAllUsesExactStagesAndStableOrder(t *testing.T) {
	graph, warnings, err := New(NewRegistry(Dependencies{})).Detect(domain.Selection{Kind: domain.SelectionAll}, fullConfig())
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Detect() warnings/error = %v, %v", warnings, err)
	}
	want := map[int][]domain.ModuleID{
		1: {"projectSettings_security"},
		2: {"projectSettings_repositories", "projectSettings_dashboards", "projectSettings_agentpools", "projectSettings_release", "projectSettings_serviceconnections", "projectSettings_test"},
		3: {"pipelines_environments", "pipelines_library", "pipelines_taskgroups", "pipelines_deploymentgroup"},
		4: {"pipelines_pipelines", "pipelines_releases"},
		5: {"projectSettings_servicehook"},
		6: {"projectSettings_settings", "projectSettings_overview"},
	}
	if len(graph.Stages) != 6 {
		t.Fatalf("stage count = %d, want 6", len(graph.Stages))
	}
	seen := map[domain.ComponentPath]bool{}
	for _, stage := range graph.Stages {
		ids := make([]domain.ModuleID, len(stage.Modules))
		for i, module := range stage.Modules {
			ids[i] = module.ID()
			if seen[module.Component()] {
				t.Errorf("component %q detected more than once", module.Component())
			}
			seen[module.Component()] = true
		}
		if !reflect.DeepEqual(ids, want[stage.Number]) {
			t.Errorf("stage %d IDs = %v, want %v", stage.Number, ids, want[stage.Number])
		}
	}
	if len(seen) != 16 {
		t.Errorf("detected %d unique components, want 16", len(seen))
	}
}

func TestDetectSelectionScopesAndOmitsEmptyStages(t *testing.T) {
	detector := New(NewRegistry(Dependencies{}))
	tests := []struct {
		name       string
		selection  domain.Selection
		wantStages []int
		wantCount  int
	}{
		{"project settings root", domain.Selection{Kind: domain.SelectionRoot, Path: "projectsettings"}, []int{1, 2, 5, 6}, 10},
		{"pipelines root", domain.Selection{Kind: domain.SelectionRoot, Path: "pipelines"}, []int{3, 4}, 6},
		{"inner component", domain.Selection{Kind: domain.SelectionComponent, Path: "projectsettings.overview"}, []int{6}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph, warnings, err := detector.Detect(tt.selection, fullConfig())
			if err != nil || len(warnings) != 0 {
				t.Fatalf("Detect() warnings/error = %v, %v", warnings, err)
			}
			if got := stageNumbers(graph); !reflect.DeepEqual(got, tt.wantStages) {
				t.Fatalf("stage numbers = %v, want %v", got, tt.wantStages)
			}
			if got := moduleCount(graph); got != tt.wantCount {
				t.Fatalf("module count = %d, want %d", got, tt.wantCount)
			}
		})
	}
}

func TestDetectEmptyRootWarnsAndInvalidSelectionsFail(t *testing.T) {
	detector := New(NewRegistry(Dependencies{}))
	for _, root := range []domain.ComponentPath{"projectsettings", "pipelines"} {
		graph, warnings, err := detector.Detect(domain.Selection{Kind: domain.SelectionRoot, Path: root}, config.Config{})
		wantWarning := "root component \"" + string(root) + "\" contains no supported inner components"
		if err != nil || len(graph.Stages) != 0 || !reflect.DeepEqual(warnings, []string{wantWarning}) {
			t.Errorf("empty root %q graph/warnings/error = %#v, %v, %v", root, graph, warnings, err)
		}
	}

	for _, selection := range []domain.Selection{
		{Kind: domain.SelectionAll, Path: "pipelines"},
		{Kind: domain.SelectionRoot, Path: "unknown"},
		{Kind: domain.SelectionComponent, Path: "pipelines.unknown"},
		{Kind: domain.SelectionComponent, Path: "pipelines.library"},
		{Kind: domain.SelectionKind("unknown")},
	} {
		_, _, err := detector.Detect(selection, config.Config{})
		var usageErr *domain.UsageError
		if !errors.As(err, &usageErr) {
			t.Errorf("Detect(%#v) error = %T, want *domain.UsageError", selection, err)
		}
	}
}

func stageNumbers(graph domain.ExecutionGraph) []int {
	numbers := make([]int, len(graph.Stages))
	for i, stage := range graph.Stages {
		numbers[i] = stage.Number
	}
	return numbers
}

func moduleCount(graph domain.ExecutionGraph) int {
	count := 0
	for _, stage := range graph.Stages {
		count += len(stage.Modules)
	}
	return count
}
