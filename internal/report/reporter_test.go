package report

import (
	"bytes"
	"errors"
	"testing"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
)

func TestReporterRendersDeterministicRedactedStageAndFinalSummaries(t *testing.T) {
	result := domain.FinalResult{Success: false, Changed: 1, Unchanged: 1, Planned: 1, Failed: 1, Results: []domain.ModuleResult{
		{Stage: 2, Module: "library", Component: "pipelines.library", Outcome: domain.OutcomePlanned, Changes: []domain.ChangeSummary{
			{Kind: domain.OperationUpdate, Resource: "z", Summary: "update variable z"},
			{Kind: domain.OperationCreate, Resource: "a", Summary: "create variable a"},
		}},
		{Stage: 1, Module: "security", Component: "projectsettings.security", Outcome: domain.OutcomeChanged,
			Changes: []domain.ChangeSummary{{Summary: "updated pat-value"}}},
		{Stage: 1, Module: "settings", Component: "projectsettings.settings", Outcome: domain.OutcomeUnchanged},
		{Stage: 1, Module: "repositories", Component: "projectsettings.repositories", Outcome: domain.OutcomeFailed,
			Err: errors.New("permission denied for password-value")},
	}}
	redactor := NewRedactor("pat-value", config.Secrets{ProjectSettings: config.ProjectSettingsSecrets{
		ServiceConnections: []config.ServiceConnectionSecret{{Password: "password-value"}},
	}})
	var output bytes.Buffer
	if err := New(&output, redactor).Render(result); err != nil {
		t.Fatal(err)
	}
	want := "Stage 1\n" +
		"  projectsettings.repositories: failed\n    error: permission denied for [REDACTED]\n" +
		"  projectsettings.security: changed\n    change: updated [REDACTED]\n" +
		"  projectsettings.settings: unchanged\n" +
		"Stage 2\n  pipelines.library: planned\n" +
		"    planned: create variable a\n    planned: update variable z\n" +
		"Final: failed (changed=1 unchanged=1 planned=1 failed=1)\n"
	if got := output.String(); got != want {
		t.Fatalf("rendered output:\n%s\nwant:\n%s", got, want)
	}
}
