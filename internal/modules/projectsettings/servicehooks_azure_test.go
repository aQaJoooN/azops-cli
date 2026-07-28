package projectsettings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/domain"
)

func TestAzureServiceHookServiceListsCreatesAndUpdatesSubscriptions(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.EscapedPath() {
		case "/collection/_apis/projects/project":
			_, _ = w.Write([]byte(`{"id":"project-id"}`))
		case "/collection/_apis/hooks/subscriptions":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"value":[{"id":"hook-id","name":"hook","publisherId":"tfs","eventType":"ms.vss-code.git-pullrequest-created-event","consumerId":"webHooks","consumerActionId":"httpRequest","publisherInputs":{"projectId":"project-id"},"consumerInputs":{"url":"https://example.invalid/hook"}},{"id":"other-consumer","name":"hook","publisherId":"tfs","consumerId":"emailHtml","consumerActionId":"sendMail","publisherInputs":{"projectId":"project-id"},"consumerInputs":{"url":"https://example.invalid/ignored"}},{"id":"other-project","name":"hook","publisherId":"tfs","consumerId":"webHooks","consumerActionId":"httpRequest","publisherInputs":{"projectId":"other-project-id"},"consumerInputs":{"url":"https://example.invalid/ignored"}}]}`))
				return
			}
			assertServiceHookRequest(t, r, "")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case "/collection/_apis/hooks/subscriptions/hook-id":
			assertServiceHookRequest(t, r, "hook-id")
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := azure.NewClient(server.URL+"/collection", "pat")
	if err != nil {
		t.Fatal(err)
	}
	service := NewAzureServiceHookService(azure.NewServices(client))

	hooks, err := service.ListServiceHooks(context.Background(), "project")
	if err != nil || len(hooks) != 1 || hooks[0].ID != "hook-id" || hooks[0].Name != "hook" {
		t.Fatalf("hooks = %#v, err = %v", hooks, err)
	}
	secret := config.ServiceHookSecret{Name: "new hook", Event: "Pull request created", URL: "https://example.invalid/new"}
	if err = service.UpsertServiceHook(context.Background(), "project", "", secret); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err = service.UpsertServiceHook(context.Background(), "project", "hook-id", secret); err != nil || requests != 6 {
		t.Fatalf("update requests = %d, err = %v", requests, err)
	}
}

func assertServiceHookRequest(t *testing.T, r *http.Request, subscriptionID string) {
	t.Helper()
	wantMethod := http.MethodPost
	if subscriptionID != "" {
		wantMethod = http.MethodPut
	}
	if r.Method != wantMethod {
		t.Errorf("method = %s, want %s", r.Method, wantMethod)
	}
	var body serviceHookSubscription
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ID != subscriptionID || body.Name != "new hook" || body.PublisherID != "tfs" || body.EventType != "ms.vss-code.git-pullrequest-created-event" || body.ConsumerID != "webHooks" || body.ConsumerActionID != "httpRequest" || body.PublisherInputs["projectId"] != "project-id" || body.ConsumerInputs["url"] != "https://example.invalid/new" {
		t.Errorf("body = %#v", body)
	}
}

func TestServiceHookPlanUpdatesBySubscriptionID(t *testing.T) {
	service := &hookMemory{current: []ServiceHook{{
		ID: "hook-id", Name: "hook", Event: "ms.vss-code.git-pullrequest-created-event", URL: "https://old.invalid",
	}}}
	module := NewServiceHook(service)
	secret := config.ServiceHookSecret{Name: "hook", Event: "Pull request created", URL: "https://new.invalid"}
	input := serviceHookInput(secret)
	plan, err := module.Plan(context.Background(), input)
	if err != nil || len(plan.Operations) != 1 || plan.Operations[0].Kind != "update" {
		t.Fatalf("plan = %#v, err = %v", plan, err)
	}
	payload, ok := plan.Operations[0].Payload.(serviceHookPayload)
	if !ok || payload.SubscriptionID != "hook-id" {
		t.Fatalf("payload = %#v", plan.Operations[0].Payload)
	}
}

func TestServiceHookPlanPreservesEqualSubscription(t *testing.T) {
	secret := config.ServiceHookSecret{Name: "hook", Event: "Pull request created", URL: "https://example.invalid/hook"}
	service := &hookMemory{current: []ServiceHook{{
		ID: "hook-id", Name: secret.Name, Event: "ms.vss-code.git-pullrequest-created-event", URL: secret.URL,
	}}}

	plan, err := NewServiceHook(service).Plan(context.Background(), serviceHookInput(secret))
	if err != nil || len(plan.Operations) != 0 {
		t.Fatalf("equal state plan = %#v, err = %v", plan, err)
	}
}

func TestServiceHookEventErrorDoesNotDiscloseSecretValue(t *testing.T) {
	secretEvent := "private unsupported event"
	_, err := serviceHookEventType(secretEvent)
	if err == nil || strings.Contains(err.Error(), secretEvent) {
		t.Fatalf("error disclosed secret event: %v", err)
	}
}

func serviceHookInput(secret config.ServiceHookSecret) domain.ModuleInput {
	return domain.ModuleInput{
		DesiredState: config.Config{
			General: config.GeneralConfig{TeamProjectName: "project"},
			ProjectSettings: config.ProjectSettingsConfig{ServiceHook: &config.CreateConfig{Create: []string{secret.Name}}},
		},
		SecretState: config.Secrets{ProjectSettings: config.ProjectSettingsSecrets{ServiceHooks: []config.ServiceHookSecret{secret}}},
	}
}