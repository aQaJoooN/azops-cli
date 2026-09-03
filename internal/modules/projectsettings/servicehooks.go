package projectsettings

import (
	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"context"
	"fmt"
	"sort"
	"strings"
)

type serviceHookModule struct{ service ServiceHookService }
type serviceHookPayload struct {
	Project        string
	SubscriptionID string
	Secret         config.ServiceHookSecret
}

type redactedServiceHookError struct{ message string }

func (e *redactedServiceHookError) Error() string { return e.message }

func NewServiceHook(service ServiceHookService) domain.Module { return &serviceHookModule{service} }
func (m *serviceHookModule) ID() domain.ModuleID              { return ServiceHookID }
func (m *serviceHookModule) Component() domain.ComponentPath  { return "projectsettings.servicehook" }
func (m *serviceHookModule) Plan(ctx context.Context, input domain.ModuleInput) (domain.Plan, error) {
	plan := domain.Plan{Module: m.ID(), Component: m.Component()}
	cfg, err := desiredConfig(input)
	if err != nil || cfg.ProjectSettings.ServiceHook == nil {
		return plan, moduleError(m, "read desired state", firstError(err, fmt.Errorf("service hook configuration is required")))
	}
	if m.service == nil {
		return plan, moduleError(m, "read current state", fmt.Errorf("service hook service is required"))
	}
	current, err := m.service.ListServiceHooks(ctx, cfg.General.TeamProjectName)
	if err != nil {
		return plan, moduleError(m, "list service hooks", err)
	}
	// Index current hooks by their idempotency key (eventType|url) — the server
	// does not persist subscription names, so we cannot match by name.
	byCurrentKey := map[string]ServiceHook{}
	for _, item := range current {
		byCurrentKey[item.Name] = item // Name holds the eventType|url key set by ListServiceHooks
	}
	bySecret := map[string][]config.ServiceHookSecret{}
	for _, item := range secretConfig(input).ProjectSettings.ServiceHooks {
		bySecret[item.Name] = append(bySecret[item.Name], item)
	}
	names := append([]string(nil), cfg.ProjectSettings.ServiceHook.Create...)
	sort.Strings(names)
	for _, name := range names {
		matchingSecrets := bySecret[name]
		if len(matchingSecrets) == 0 {
			return plan, moduleError(m, "match service hook secret", fmt.Errorf("missing same-name secret entry for %q", name))
		}
		if len(matchingSecrets) != 1 {
			return plan, moduleError(m, "match service hook secret", fmt.Errorf("service hook %q matches %d secret entries; exactly one is required", name, len(matchingSecrets)))
		}
		secret := matchingSecrets[0]
		desiredEvent, err := serviceHookEventType(secret.Event)
		if err != nil {
			return plan, moduleError(m, "resolve service hook event", err)
		}
		// Look up current hook by its idempotency key.
		key := serviceHookKey(desiredEvent, secret.URL)
		existing, exists := byCurrentKey[key]
		desired := ServiceHook{Event: desiredEvent, URL: secret.URL}
		if !exists || !sameServiceHook(existing, desired) {
			kind := domain.OperationCreate
			subscriptionID := ""
			if exists {
				kind = domain.OperationUpdate
				subscriptionID = existing.ID
				if subscriptionID == "" {
					return plan, moduleError(m, "update service hook", fmt.Errorf("service hook %q has no subscription ID", name))
				}
			}
			plan.Operations = append(plan.Operations, domain.Operation{Kind: kind, Resource: name, Summary: string(kind) + " service hook " + name, Payload: serviceHookPayload{cfg.General.TeamProjectName, subscriptionID, secret}})
		}
	}
	return plan, nil
}
func (m *serviceHookModule) Apply(ctx context.Context, plan domain.Plan) (domain.ApplyResult, error) {
	result := domain.ApplyResult{}
	for _, op := range plan.Operations {
		p, ok := op.Payload.(serviceHookPayload)
		if !ok {
			return result, moduleError(m, "apply plan", fmt.Errorf("unsupported service hook operation payload"))
		}
		if err := m.service.UpsertServiceHook(ctx, p.Project, p.SubscriptionID, p.Secret); err != nil {
			return result, moduleError(m, "upsert service hook", redactServiceHookError(err, p.Secret))
		}
		result.Changes = append(result.Changes, domain.ChangeSummary{Kind: op.Kind, Resource: op.Resource, Summary: op.Summary})
	}
	return result, nil
}

func redactServiceHookError(err error, secret config.ServiceHookSecret) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	values := []string{secret.Name, secret.Event, secret.URL}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, value := range values {
		if value != "" {
			message = strings.ReplaceAll(message, value, "[REDACTED]")
		}
	}
	return &redactedServiceHookError{message: message}
}
