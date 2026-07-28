package projectsettings

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
)

// AzureServiceHookService reconciles web-hook subscriptions through the
// Azure DevOps Server service hooks API.
type AzureServiceHookService struct {
	projects *azure.Adapter
	hooks    *azure.Adapter
}

func NewAzureServiceHookService(services azure.Services) *AzureServiceHookService {
	return &AzureServiceHookService{projects: services.Projects, hooks: services.ServiceHooks}
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
			ID: subscription.ID, Name: subscription.Name,
			Event: subscription.EventType, URL: subscription.ConsumerInputs["url"],
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
	payload := serviceHookSubscription{
		Name: secret.Name, PublisherID: "tfs", EventType: eventType, ResourceVersion: "1.0",
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

func sameServiceHook(current, desired ServiceHook) bool {
	return current.Name == desired.Name && current.Event == desired.Event && current.URL == desired.URL
}

func serviceHookEventType(value string) (string, error) {
	if strings.HasPrefix(value, "ms.vss-") {
		return value, nil
	}
	events := map[string]string{
		"pull request commented on": "ms.vss-code.git-pullrequest-comment-event",
		"pull request created":      "ms.vss-code.git-pullrequest-created-event",
		"pull request updated":      "ms.vss-code.git-pullrequest-updated-event",
	}
	if eventType := events[strings.ToLower(strings.TrimSpace(value))]; eventType != "" {
		return eventType, nil
	}
	return "", fmt.Errorf("unsupported service hook event; expected a supported pull request event or Azure DevOps event type")
}