package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"azops-cli/internal/domain"
)

func TestLoaderDiscoveryPrecedenceAndOptionalSecret(t *testing.T) {
	dir := t.TempDir()
	cli := writeTestFile(t, dir, "cli.yaml", validConfigYAML("cli"))
	env := writeTestFile(t, dir, "env.yaml", validConfigYAML("env"))
	writeTestFile(t, dir, "config.yaml", validConfigYAML("yaml"))
	writeTestFile(t, dir, "config.yml", validConfigYAML("yml"))

	loader := Loader{LookupEnv: func(key string) string {
		if key == "AZOPS_CONFIG_FILE" { return env }
		return ""
	}}
	loaded, err := loader.Load(context.Background(), LoadOptions{ConfigPath: cli, WorkingDir: dir})
	if err != nil { t.Fatal(err) }
	if loaded.Config.General.TeamProjectName != "cli" { t.Fatalf("CLI path did not win: %q", loaded.Config.General.TeamProjectName) }
	if len(loaded.Warnings) != 1 || loaded.Warnings[0] != MissingSecretWarning { t.Fatalf("unexpected warnings: %v", loaded.Warnings) }

	loaded, err = loader.Load(context.Background(), LoadOptions{WorkingDir: dir})
	if err != nil { t.Fatal(err) }
	if loaded.Config.General.TeamProjectName != "env" { t.Fatalf("environment path did not win: %q", loaded.Config.General.TeamProjectName) }

	loader.LookupEnv = func(string) string { return "" }
	loaded, err = loader.Load(context.Background(), LoadOptions{WorkingDir: dir})
	if err != nil { t.Fatal(err) }
	if loaded.Config.General.TeamProjectName != "yaml" { t.Fatalf(".yaml did not win: %q", loaded.Config.General.TeamProjectName) }

	if err := os.Remove(filepath.Join(dir, "config.yaml")); err != nil { t.Fatal(err) }
	loaded, err = loader.Load(context.Background(), LoadOptions{WorkingDir: dir})
	if err != nil { t.Fatal(err) }
	if loaded.Config.General.TeamProjectName != "yml" { t.Fatalf(".yml fallback was not selected: %q", loaded.Config.General.TeamProjectName) }
}

func TestLoaderSecretDiscoveryPrecedence(t *testing.T) {
	dir := t.TempDir()
	configPath := writeTestFile(t, dir, "desired.yaml", validConfigYAML("project"))
	cli := writeTestFile(t, dir, "cli-secret.yaml", validSecretYAML("cli"))
	env := writeTestFile(t, dir, "env-secret.yaml", validSecretYAML("env"))
	writeTestFile(t, dir, "secret.yaml", validSecretYAML("yaml"))
	writeTestFile(t, dir, "secret.yml", validSecretYAML("yml"))

	loader := Loader{LookupEnv: func(key string) string {
		if key == "AZOPS_SECRET_FILE" { return env }
		return ""
	}}
	loaded, err := loader.Load(context.Background(), LoadOptions{ConfigPath: configPath, SecretPath: cli, WorkingDir: dir})
	if err != nil { t.Fatal(err) }
	if got := loaded.Secrets.ProjectSettings.ServiceHooks[0].Event; got != "cli" { t.Fatalf("CLI secret path did not win: %q", got) }

	loaded, err = loader.Load(context.Background(), LoadOptions{ConfigPath: configPath, WorkingDir: dir})
	if err != nil { t.Fatal(err) }
	if got := loaded.Secrets.ProjectSettings.ServiceHooks[0].Event; got != "env" { t.Fatalf("environment secret path did not win: %q", got) }

	loader.LookupEnv = func(string) string { return "" }
	loaded, err = loader.Load(context.Background(), LoadOptions{ConfigPath: configPath, WorkingDir: dir})
	if err != nil { t.Fatal(err) }
	if got := loaded.Secrets.ProjectSettings.ServiceHooks[0].Event; got != "yaml" { t.Fatalf("secret.yaml did not win: %q", got) }

	if err := os.Remove(filepath.Join(dir, "secret.yaml")); err != nil { t.Fatal(err) }
	loaded, err = loader.Load(context.Background(), LoadOptions{ConfigPath: configPath, WorkingDir: dir})
	if err != nil { t.Fatal(err) }
	if got := loaded.Secrets.ProjectSettings.ServiceHooks[0].Event; got != "yml" { t.Fatalf("secret.yml fallback was not selected: %q", got) }
}

func TestLoaderReturnsTypedDiscoveryErrors(t *testing.T) {
	dir := t.TempDir()
	loader := Loader{LookupEnv: func(string) string { return "" }}

	_, err := loader.Load(context.Background(), LoadOptions{WorkingDir: dir})
	var discoveryErr *domain.DiscoveryError
	if !errors.As(err, &discoveryErr) { t.Fatalf("missing config: expected DiscoveryError, got %T: %v", err, err) }

	configPath := writeTestFile(t, dir, "config.yaml", validConfigYAML("project"))
	_, err = loader.Load(context.Background(), LoadOptions{ConfigPath: configPath, SecretPath: filepath.Join(dir, "missing-secret.yaml")})
	if !errors.As(err, &discoveryErr) { t.Fatalf("missing explicit secret: expected DiscoveryError, got %T: %v", err, err) }
}

func TestLoaderRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "config.yaml", validConfigYAML("project")+"unknown: true\n")
	_, err := (Loader{LookupEnv: func(string) string { return "" }}).Load(context.Background(), LoadOptions{ConfigPath: path, WorkingDir: dir})
	var decodeErr *domain.DecodeError
	if !errors.As(err, &decodeErr) { t.Fatalf("expected DecodeError, got %T: %v", err, err) }
}

func TestLoaderRejectsMalformedAndMultipleYAMLDocuments(t *testing.T) {
	dir := t.TempDir()
	loader := Loader{LookupEnv: func(string) string { return "" }}
	for _, test := range []struct {
		name string
		yaml string
	}{
		{name: "malformed", yaml: "general: [\n"},
		{name: "multiple documents", yaml: validConfigYAML("project") + "---\ngeneral: {}\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeTestFile(t, dir, test.name+".yaml", test.yaml)
			_, err := loader.Load(context.Background(), LoadOptions{ConfigPath: path, WorkingDir: dir})
			var decodeErr *domain.DecodeError
			if !errors.As(err, &decodeErr) { t.Fatalf("expected DecodeError, got %T: %v", err, err) }
		})
	}
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { t.Fatal(err) }
	return path
}

func validConfigYAML(project string) string {
	return "general:\n  teamprojectname: " + project + "\n  groupsalias:\n    Dev:\n      Readers: \"14\"\n  groupnametemplate: teamprojectname team role\n"
}

func validSecretYAML(event string) string {
	return "projectsettings:\n  servicehook:\n    - name: hook\n      event: " + event + "\n      url: https://example.test/hook\n"
}
