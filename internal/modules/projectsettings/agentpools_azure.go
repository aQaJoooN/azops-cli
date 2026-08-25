package projectsettings

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/modules/permissions"
)

// agentQueueRoleScope is the confirmed security role scope for project-level agent queues.
const agentQueueRoleScope = "distributedtask.agentqueuerole"

// AzureAgentPoolService implements AgentPoolService using the securityroles API.
// Read/write: /_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/{projectId}_{queueId}
type AzureAgentPoolService struct {
	distributedTask *azure.Adapter
	securityRoles   *azure.Adapter
	projects        *azure.Adapter
	groups          permissions.GroupDirectory
}

func NewAzureAgentPoolService(services azure.Services, groups permissions.GroupDirectory) *AzureAgentPoolService {
	return &AzureAgentPoolService{
		distributedTask: services.DistributedTask,
		securityRoles:   services.SecurityRoles,
		projects:        services.Projects,
		groups:          groups,
	}
}

// resolveProjectID fetches the project GUID for a given project name.
func (s *AzureAgentPoolService) resolveProjectID(ctx context.Context, project string) (string, error) {
	var resp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := s.projects.Do(ctx, azure.Request{Path: "", APIVersion: "7.0"}, &resp); err != nil {
		return "", fmt.Errorf("list projects: %w", err)
	}
	for _, p := range resp.Value {
		if strings.EqualFold(p.Name, project) {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("project %q not found", project)
}

// resolveQueueID finds the project-level queue ID for a named pool.
func (s *AzureAgentPoolService) resolveQueueID(ctx context.Context, project, poolName string) (int, error) {
	var resp struct {
		Value []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := s.distributedTask.Do(ctx, azure.Request{Project: project, Path: "queues"}, &resp); err != nil {
		return 0, fmt.Errorf("list agent queues: %w", err)
	}
	for _, q := range resp.Value {
		if q.Name == poolName {
			return q.ID, nil
		}
	}
	return 0, fmt.Errorf("agent pool %q not found in project %q", poolName, project)
}

// ReadAgentPoolRoles reads current role assignments for a queue, keyed by descriptor.
func (s *AzureAgentPoolService) ReadAgentPoolRoles(ctx context.Context, project, poolName string) (map[string]config.Role, error) {
	if s == nil || s.distributedTask == nil || s.securityRoles == nil {
		return nil, fmt.Errorf("Azure agent pool adapters are required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return nil, err
	}
	queueID, err := s.resolveQueueID(ctx, project, poolName)
	if err != nil {
		return nil, err
	}
	resource := fmt.Sprintf("%s_%d", projectID, queueID)

	var resp struct {
		Value []struct {
			Identity struct {
				ID string `json:"id"`
			} `json:"identity"`
			Role struct {
				Name string `json:"name"`
			} `json:"role"`
			Access string `json:"access"`
		} `json:"value"`
	}
	if err := s.securityRoles.Do(ctx, azure.Request{
		Path:       fmt.Sprintf("scopes/%s/roleassignments/resources/%s", agentQueueRoleScope, resource),
		APIVersion: "5.0-preview.1",
	}, &resp); err != nil {
		return nil, fmt.Errorf("read agent pool roles for %q: %w", poolName, err)
	}

	// Build TFID → descriptor map from the group directory.
	allGroups, err := s.groups.ListGroups(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("list groups for agent pool role mapping: %w", err)
	}
	tfidToDescriptor := make(map[string]string, len(allGroups))
	for _, g := range allGroups {
		tfidToDescriptor[g.TFID] = g.Descriptor
	}

	result := make(map[string]config.Role, len(resp.Value))
	for _, r := range resp.Value {
		// Only count explicitly assigned roles, not inherited ones.
		if r.Access != "assigned" {
			continue
		}
		descriptor, ok := tfidToDescriptor[r.Identity.ID]
		if !ok {
			descriptor = r.Identity.ID
		}
		result[descriptor] = config.Role(r.Role.Name)
	}
	return result, nil
}

// SetAgentPoolRoles applies role assignments using PUT securityroles.
func (s *AzureAgentPoolService) SetAgentPoolRoles(ctx context.Context, project, poolName string, changes []permissions.RoleChange) error {
	if s == nil || s.distributedTask == nil || s.securityRoles == nil {
		return fmt.Errorf("Azure agent pool adapters are required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return err
	}
	queueID, err := s.resolveQueueID(ctx, project, poolName)
	if err != nil {
		return err
	}
	resource := fmt.Sprintf("%s_%d", projectID, queueID)

	type roleEntry struct {
		UserID   string `json:"userId"`
		RoleName string `json:"roleName"`
	}
	entries := make([]roleEntry, 0, len(changes))
	for _, change := range changes {
		entries = append(entries, roleEntry{
			UserID:   change.Principal.TFID,
			RoleName: string(change.Desired),
		})
	}

	if err := s.securityRoles.Do(ctx, azure.Request{
		Path:       fmt.Sprintf("scopes/%s/roleassignments/resources/%s", agentQueueRoleScope, resource),
		Method:     http.MethodPut,
		APIVersion: "5.0-preview.1",
		Body:       entries,
	}, nil); err != nil {
		return fmt.Errorf("set agent pool roles for %q: %w", poolName, err)
	}
	return nil
}
