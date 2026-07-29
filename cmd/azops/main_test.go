package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testPAT       = "integration-pat-value"
	testSecretURL = "https://secret.example/integration-value"
)

func TestRunDryRunReportsPlannedChangeWithoutMutation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		assertGraphRequest(t, request)
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"identities":[]}`)
	}))
	defer server.Close()

	code, stdout, stderr := runIntegrationSelection(t, server.URL, "all", validApplicationConfig("project"))
	if code != exitSuccess {
		t.Fatalf("run exit = %d, stderr = %s", code, stderr)
	}
	if requests.Load() != 1 {
		t.Fatalf("HTTP requests = %d, want one read", requests.Load())
	}
	for _, expected := range []string{
		"Stage 1", "projectsettings.security: planned",
		"planned: create project group project Dev Readers",
		"Final: success (changed=0 unchanged=0 planned=1 failed=0)",
	} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("stdout missing %q:\n%s", expected, stdout)
		}
	}
}

func TestRunDryRunReportsNoOp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/project/_api/_identity/ReadScopedApplicationGroupsJson" {
			assertGraphRequest(t, request)
			fmt.Fprint(writer, `{"identities":[{"FriendlyDisplayName":"project Dev Readers","TeamFoundationId":"group-id"}]}`)
			return
		}
		if request.URL.Path == "/project/_api/_identity/Display" && request.URL.Query().Get("tfid") == "group-id" {
			fmt.Fprint(writer, `{"security":{"descriptorIdentityType":"type","descriptorIdentifier":"group-14"}}`)
			return
		}
		http.NotFound(writer, request)
	}))
	defer server.Close()

	code, stdout, stderr := runIntegration(t, server.URL, validApplicationConfig("project"))
	if code != exitSuccess || stderr != "" {
		t.Fatalf("run exit/stderr = %d, %q", code, stderr)
	}
	if !strings.Contains(stdout, "projectsettings.security: unchanged") ||
		!strings.Contains(stdout, "Final: success (changed=0 unchanged=1 planned=0 failed=0)") {
		t.Fatalf("unexpected no-op output:\n%s", stdout)
	}
}
func TestRunValidationFailureMakesNoAPIRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	configYAML := validApplicationConfig("project") + "  servicehook:\n    create:\n      - required-hook\n"
	code, _, stderr := runIntegrationSelection(t, server.URL, "projectsettings.servicehook", configYAML)
	if code != exitFailure || !strings.Contains(stderr, "missing same-name secret entry") {
		t.Fatalf("run exit/stderr = %d, %q", code, stderr)
	}
	if requests.Load() != 0 {
		t.Fatalf("validation failure sent %d API requests", requests.Load())
	}
}

func TestRunAPIFailureIsReportedAndRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assertGraphRequest(t, request)
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(writer, "request failed for %s and %s", testPAT, testSecretURL)
	}))
	defer server.Close()

	code, stdout, stderr := runIntegration(t, server.URL, validApplicationConfig("project"))
	if code != exitFailure || stderr != "" {
		t.Fatalf("run exit/stderr = %d, %q", code, stderr)
	}
	if !strings.Contains(stdout, "projectsettings.security: failed") ||
		!strings.Contains(stdout, "Azure DevOps API returned status 500") ||
		!strings.Contains(stdout, "Final: failed") {
		t.Fatalf("unexpected API failure output:\n%s", stdout)
	}
	if strings.Contains(stdout, testPAT) || strings.Contains(stdout, testSecretURL) {
		t.Fatalf("output disclosed a credential:\n%s", stdout)
	}
}

func runIntegration(t *testing.T, serverURL, configYAML string) (int, string, string) {
	t.Helper()
	return runIntegrationSelection(t, serverURL, "projectsettings.security", configYAML)
}

func runIntegrationSelection(t *testing.T, serverURL, selection, configYAML string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := writeFixture(t, dir, "config.yaml", configYAML)
	secretPath := writeFixture(t, dir, "secret.yaml", "projectsettings:\n  servicehook:\n    - name: unused\n      event: event\n      url: "+testSecretURL+"\n")
	values := map[string]string{"AZOPS_AZURE_PAT": testPAT}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"apply", selection, "--config", configPath, "--secret", secretPath, "--url", serverURL, "--dry-run"}, &stdout, &stderr, lookup, dir)
	return code, stdout.String(), stderr.String()
}

func validApplicationConfig(project string) string {
	return "general:\n" +
		"  teamprojectname: " + project + "\n" +
		"  groupsalias:\n    Dev:\n      Readers: \"14\"\n" +
		"  groupnametemplate: teamprojectname team role\n" +
		"projectsettings:\n  security:\n    creategroup: true\n"
}

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertGraphRequest(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodGet || request.URL.Path != "/project/_api/_identity/ReadScopedApplicationGroupsJson" || request.URL.Query().Get("__v") != "5" || request.URL.Query().Get("api-version") != "7.0" {
		t.Errorf("unexpected identity request %s %s", request.Method, request.URL.String())
	}
	_, password, ok := request.BasicAuth()
	if !ok || password != testPAT {
		t.Errorf("request did not use PAT authentication")
	}
}
