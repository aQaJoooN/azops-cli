package cli

import (
	"errors"
	"testing"

	"azops-cli/internal/domain"
)

func TestParseSelectors(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want domain.Selection
	}{
		{"all", "all", domain.Selection{Kind: domain.SelectionAll}},
		{"root", "projectsettings", domain.Selection{Kind: domain.SelectionRoot, Path: "projectsettings"}},
		{"inner", "pipelines.library", domain.Selection{Kind: domain.SelectionComponent, Path: "pipelines.library"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]string{"apply", tt.arg})
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got.Selection != tt.want {
				t.Fatalf("Parse() selection = %#v, want %#v", got.Selection, tt.want)
			}
		})
	}
}

func TestParseRejectsInvalidCommands(t *testing.T) {
	for _, args := range [][]string{
		{"apply"},
		{"apply", "unknown"},
		{"apply", "projectsettings.unknown"},
		{"plan", "all"},
	} {
		_, err := Parse(args)
		var usageErr *domain.UsageError
		if !errors.As(err, &usageErr) {
			t.Errorf("Parse(%q) error = %T, want *domain.UsageError", args, err)
		}
	}
}
func TestParseOptions(t *testing.T) {
	got, err := Parse([]string{
		"apply", "all", "-c", "config.yml", "--secret=secret.yml",
		"-u", "https://option.example/collection", "--dry-run",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.ConfigPath != "config.yml" || got.SecretPath != "secret.yml" {
		t.Fatalf("Parse() paths = %q, %q", got.ConfigPath, got.SecretPath)
	}
	if got.URL != "https://option.example/collection" || !got.DryRun {
		t.Fatalf("Parse() URL/DryRun = %q, %t", got.URL, got.DryRun)
	}

	got, err = Parse([]string{"apply", "pipelines", "--config", "c.yaml", "-s", "s.yaml", "--url", "https://long.example"})
	if err != nil {
		t.Fatalf("Parse() long options error = %v", err)
	}
	if got.ConfigPath != "c.yaml" || got.SecretPath != "s.yaml" || got.URL != "https://long.example" {
		t.Fatalf("Parse() long options = %#v", got)
	}
}

func TestResolveConnection(t *testing.T) {
	t.Run("option URL takes precedence", func(t *testing.T) {
		lookup := environment(map[string]string{
			"AZOPS_AZURE_URL": "https://environment.example/collection",
			"AZOPS_AZURE_PAT": "pat-value",
		})
		got, err := ResolveConnection("https://option.example/collection", lookup)
		if err != nil {
			t.Fatalf("ResolveConnection() error = %v", err)
		}
		if got.URL.String() != "https://option.example/collection" || got.PAT != "pat-value" {
			t.Fatalf("ResolveConnection() = %#v", got)
		}
	})

	t.Run("environment URL is used without option", func(t *testing.T) {
		lookup := environment(map[string]string{
			"AZOPS_AZURE_URL": "https://environment.example/collection",
			"AZOPS_AZURE_PAT": "pat-value",
		})
		got, err := ResolveConnection("", lookup)
		if err != nil {
			t.Fatalf("ResolveConnection() error = %v", err)
		}
		if got.URL.String() != "https://environment.example/collection" || got.PAT != "pat-value" {
			t.Fatalf("ResolveConnection() = %#v", got)
		}
	})

	for _, tt := range []struct {
		name   string
		url    string
		values map[string]string
	}{
		{"missing URL", "", map[string]string{"AZOPS_AZURE_PAT": "pat-value"}},
		{"missing PAT", "https://server.example", nil},
		{"invalid URL", "://bad", map[string]string{"AZOPS_AZURE_PAT": "pat-value"}},
		{"relative URL", "server/path", map[string]string{"AZOPS_AZURE_PAT": "pat-value"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveConnection(tt.url, environment(tt.values))
			var connectionErr *domain.ConnectionError
			if !errors.As(err, &connectionErr) {
				t.Fatalf("ResolveConnection() error = %T, want *domain.ConnectionError", err)
			}
		})
	}
}

func environment(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
