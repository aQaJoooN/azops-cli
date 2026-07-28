package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"azops-cli/internal/domain"
)

func TestAdapterBuildsAuthenticatedProjectRequest(t *testing.T) {
	const pat = "test-pat"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.EscapedPath() != "/collection/Team%20Project/_apis/build/definitions/Folder%20One" {
			t.Errorf("path = %q", request.URL.EscapedPath())
		}
		if request.URL.Query().Get("api-version") != "7.0" || request.URL.Query().Get("name") != "build one" {
			t.Errorf("query = %q", request.URL.RawQuery)
		}
		expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+pat))
		if request.Header.Get("Authorization") != expectedAuth {
			t.Errorf("authorization header is invalid")
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["name"] != "definition" {
			t.Errorf("body = %#v, err = %v", body, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":42}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL+"/collection", pat)
	if err != nil {
		t.Fatal(err)
	}
	var result struct{ ID int `json:"id"` }
	err = NewAdapter(client, Build).Do(context.Background(), Request{
		Project: "Team Project", Method: http.MethodPost, Path: "definitions/Folder One",
		Query: url.Values{"name": {"build one"}}, Body: map[string]string{"name": "definition"},
	}, &result)
	if err != nil || result.ID != 42 {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}
func TestClientHonorsContextAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "pat", WithTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	err = client.Do(context.Background(), Request{Service: Projects}, nil)
	var connectionError *domain.ConnectionError
	if !errors.As(err, &connectionError) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout connection error, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = client.Do(ctx, Request{Service: Projects}, nil)
	if !errors.As(err, &connectionError) || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected canceled connection error, got %v", err)
	}
}

func TestClientReturnsBoundedSanitizedAPIError(t *testing.T) {
	const pat = "private-token"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-TFS-Session", "request-id")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte("failure " + pat + " and trailing details"))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, pat, WithErrorBodyLimit(20))
	if err != nil {
		t.Fatal(err)
	}
	err = client.Do(context.Background(), Request{Service: Projects}, nil)
	var apiError *domain.APIError
	if !errors.As(err, &apiError) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiError.StatusCode != http.StatusBadRequest || apiError.RequestID != "request-id" {
		t.Fatalf("API error = %#v", apiError)
	}
	if strings.Contains(err.Error(), pat) || !strings.Contains(err.Error(), "[REDACTED]") || !strings.HasSuffix(apiError.Message, "…") {
		t.Fatalf("error was not bounded and sanitized: %q", err)
	}
}

func TestServicesUseServerCompatibleVersionsAndScopes(t *testing.T) {
	services := []Service{Projects, Identity, Graph, Security, Build, Release, DistributedTask, ServiceHooks, Dashboards, ServiceEndpoints, Test}
	for _, service := range services {
		if service.APIVersion == "" || service.Name == "" || len(service.Prefix) == 0 {
			t.Errorf("incomplete service: %#v", service)
		}
	}
	if Build.Scope != ProjectScope || Projects.Scope != CollectionScope {
		t.Fatal("service scopes are invalid")
	}
	var unsupported *UnsupportedOperationError
	if !errors.As(Unsupported(Dashboards, "write"), &unsupported) {
		t.Fatal("unsupported operations must return a typed error")
	}
}
