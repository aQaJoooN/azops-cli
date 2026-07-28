package report

import (
	"bytes"
	"testing"

	"azops-cli/internal/config"
)

func TestRedactorCoversPATSecretScalarsAndWarnings(t *testing.T) {
	secrets := config.Secrets{ProjectSettings: config.ProjectSettingsSecrets{
		ServiceConnections: []config.ServiceConnectionSecret{{
			Name: "connection-name", Password: "password-value", Token: "token-value",
		}},
	}}
	redactor := NewRedactor("pat-value", secrets)
	input := "pat=pat-value password=password-value token=token-value empty="
	want := "pat=[REDACTED] password=[REDACTED] token=[REDACTED] empty="
	if got := redactor.Redact(input); got != want {
		t.Fatalf("Redact() = %q, want %q", got, want)
	}

	var output bytes.Buffer
	if err := New(&output, redactor).Warning("request pat-value used password-value"); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "Warning: request [REDACTED] used [REDACTED]\n"; got != want {
		t.Fatalf("warning = %q, want %q", got, want)
	}
}
