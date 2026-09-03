package projectsettings

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
)

// AzureServiceHookService reconciles web-hook subscriptions through the
// Azure DevOps Server service hooks API.
type AzureServiceHookService struct {
	projects *azure.Adapter
	hooks    *azure.Adapter

	// resourceVersionCache caches the latest supported resource version per event type.
	rvMu    sync.Mutex
	rvCache map[string]string
}

func NewAzureServiceHookService(services azure.Services) *AzureServiceHookService {
	return &AzureServiceHookService{
		projects: services.Projects,
		hooks:    services.ServiceHooks,
		rvCache:  make(map[string]string),
	}
}

type serviceHookSubscription struct {
	ID               string            `json:"id,omitempty"`
	Name             string            `json:"name,omitempty"`
	PublisherID      string            `json:"publisherId,omitempty"`
	EventType        string            `json:"eventType"`
	ResourceVersion  string            `json:"resourceVersion,omitempty"`
	ConsumerID       string            `json:"consumerId,omitempty"`
	ConsumerActionID string            `json:"consumerActionId,omitempty"`
	PublisherInputs  map[string]string `json:"publisherInputs"`
	ConsumerInputs   map[string]string `json:"consumerInputs"`
}

type serviceHookSubscriptions struct {
	Value []serviceHookSubscription `json:"value"`
}

func (s *AzureServiceHookService) projectID(ctx context.Context, project string) (string, error) {
	if s == nil || s.projects == nil || s.hooks == nil {
		return "", fmt.Errorf("Azure service hook adapters are required")
	}
	var result struct {
		ID string `json:"id"`
	}
	if err := s.projects.Do(ctx, azure.Request{Path: project}, &result); err != nil {
		return "", err
	}
	if result.ID == "" {
		return "", fmt.Errorf("project %q has no ID", project)
	}
	return result.ID, nil
}

// latestResourceVersion queries the publisher event type API and returns the first
// (latest) supported resource version for the given event type.
// Results are cached so the API is called at most once per event type per run.
func (s *AzureServiceHookService) latestResourceVersion(ctx context.Context, eventType string) (string, error) {
	s.rvMu.Lock()
	if v, ok := s.rvCache[eventType]; ok {
		s.rvMu.Unlock()
		return v, nil
	}
	s.rvMu.Unlock()

	var result struct {
		SupportedResourceVersions []string `json:"supportedResourceVersions"`
	}
	if err := s.hooks.Do(ctx, azure.Request{
		Path: "publishers/tfs/eventTypes/" + eventType,
	}, &result); err != nil {
		return "", fmt.Errorf("fetch resource versions for event %q: %w", eventType, err)
	}
	version := "1.0"
	if len(result.SupportedResourceVersions) > 0 {
		version = result.SupportedResourceVersions[0]
	}

	s.rvMu.Lock()
	s.rvCache[eventType] = version
	s.rvMu.Unlock()
	return version, nil
}

func (s *AzureServiceHookService) ListServiceHooks(ctx context.Context, project string) ([]ServiceHook, error) {
	projectID, err := s.projectID(ctx, project)
	if err != nil {
		return nil, err
	}
	var response serviceHookSubscriptions
	if err := s.hooks.Do(ctx, azure.Request{Path: "subscriptions"}, &response); err != nil {
		return nil, err
	}
	hooks := make([]ServiceHook, 0, len(response.Value))
	for _, subscription := range response.Value {
		if subscription.PublisherID != "tfs" ||
			subscription.ConsumerID != "webHooks" ||
			subscription.ConsumerActionID != "httpRequest" ||
			subscription.PublisherInputs["projectId"] != projectID ||
			subscription.ConsumerInputs["url"] == "" {
			continue
		}
		hooks = append(hooks, ServiceHook{
			ID:    subscription.ID,
			Name:  serviceHookKey(subscription.EventType, subscription.ConsumerInputs["url"]),
			Event: subscription.EventType,
			URL:   subscription.ConsumerInputs["url"],
		})
	}
	return hooks, nil
}

func (s *AzureServiceHookService) UpsertServiceHook(ctx context.Context, project, subscriptionID string, secret config.ServiceHookSecret) error {
	projectID, err := s.projectID(ctx, project)
	if err != nil {
		return err
	}
	eventType, err := serviceHookEventType(secret.Event)
	if err != nil {
		return err
	}
	resourceVersion, err := s.latestResourceVersion(ctx, eventType)
	if err != nil {
		return err
	}
	payload := serviceHookSubscription{
		Name: secret.Name, PublisherID: "tfs", EventType: eventType, ResourceVersion: resourceVersion,
		ConsumerID: "webHooks", ConsumerActionID: "httpRequest",
		PublisherInputs: map[string]string{"projectId": projectID},
		ConsumerInputs:  map[string]string{"url": secret.URL},
	}
	method, path := http.MethodPost, "subscriptions"
	if subscriptionID != "" {
		method, path = http.MethodPut, "subscriptions/"+subscriptionID
		payload.ID = subscriptionID
	}
	return s.hooks.Do(ctx, azure.Request{Method: method, Path: path, Body: payload}, nil)
}

// serviceHookKey returns the stable idempotency key for a subscription.
// The server does not persist the name field, so we key on eventType+url.
func serviceHookKey(eventType, url string) string {
	return eventType + "|" + url
}

// sameServiceHook reports whether two hooks have the same event type and URL.
func sameServiceHook(current, desired ServiceHook) bool {
	return current.Event == desired.Event && current.URL == desired.URL
}

func serviceHookEventType(value string) (string, error) {
	// Pass through raw event type IDs (both ms.vss- and git./tfvc./workitem. prefixes).
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"ms.vss-", "git.", "tfvc.", "workitem.", "build.", "rm.", "distributedtask."} {
		if strings.HasPrefix(normalized, prefix) {
			return value, nil
		}
	}
	events := map[string]string{
		"pull request commented on": "ms.vss-code.git-pullrequest-comment-event",
		"pull request created":      "git.pullrequest.created",
		"pull request updated":      "git.pullrequest.updated",
	}
	if eventType := events[normalized]; eventType != "" {
		return eventType, nil
	}
	return "", fmt.Errorf("unsupported service hook event; expected a supported pull request event or Azure DevOps event type")
}
