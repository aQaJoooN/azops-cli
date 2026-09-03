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

// serviceEndpointRoleScope is the security role scope for project-level service endpoint (connection) roles.
// This scope supports Administrator, Creator, User, and Reader roles.
const serviceEndpointRoleScope = "distributedtask.project.serviceendpointrole"

// AzureServiceConnectionService implements ServiceConnectionService.
// Permissions use: /_apis/securityroles/scopes/distributedtask.project.serviceendpointrole/roleassignments/resources/{projectId}
// Listing uses:    /{project}/_apis/serviceendpoint/endpoints
type AzureServiceConnectionService struct {
	serviceEndpoints *azure.Adapter
	securityRoles    *azure.Adapter
	projects         *azure.Adapter
	pipelinePerms    *azure.Adapter
	groups           permissions.GroupDirectory
}

func NewAzureServiceConnectionService(services azure.Services, groups permissions.GroupDirectory) *AzureServiceConnectionService {
	return &AzureServiceConnectionService{
		serviceEndpoints: services.ServiceEndpoints,
		securityRoles:    services.SecurityRoles,
		projects:         services.Projects,
		pipelinePerms:    services.PipelinePerms,
		groups:           groups,
	}
}

// resolveProjectID fetches the project GUID for a given project name.
func (s *AzureServiceConnectionService) resolveProjectID(ctx context.Context, project string) (string, error) {
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

// ListServiceConnections lists existing service endpoints in the project,
// including their pipeline grant_access state.
func (s *AzureServiceConnectionService) ListServiceConnections(ctx context.Context, project string) ([]ServiceConnection, error) {
	if s == nil || s.serviceEndpoints == nil {
		return nil, fmt.Errorf("service endpoints adapter is required")
	}
	var resp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
			URL  string `json:"url"`
			Authorization struct {
				Scheme string `json:"scheme"`
			} `json:"authorization"`
		} `json:"value"`
	}
	if err := s.serviceEndpoints.Do(ctx, azure.Request{
		Project: project,
		Path:    "endpoints",
	}, &resp); err != nil {
		return nil, fmt.Errorf("list service connections: %w", err)
	}
	result := make([]ServiceConnection, 0, len(resp.Value))
	for _, e := range resp.Value {
		grantAccess := false
		if s.pipelinePerms != nil {
			var pp struct {
				AllPipelines *struct {
					Authorized bool `json:"authorized"`
				} `json:"allPipelines"`
			}
			if err := s.pipelinePerms.Do(ctx, azure.Request{
				Project: project,
				Path:    "endpoint/" + e.ID,
			}, &pp); err == nil && pp.AllPipelines != nil {
				grantAccess = pp.AllPipelines.Authorized
			}
		}
		result = append(result, ServiceConnection{
			Name:        e.Name,
			ID:          e.ID,
			Type:        e.Type,
			URL:         e.URL,
			Auth:        e.Authorization.Scheme,
			GrantAccess: grantAccess,
		})
	}
	return result, nil
}

// UpsertServiceConnection creates or updates a service connection based on the secret config.
// It also sets grant_access (pipeline permissions) after create/update.
func (s *AzureServiceConnectionService) UpsertServiceConnection(ctx context.Context, project string, secret config.ServiceConnectionSecret) error {
	if s == nil || s.serviceEndpoints == nil {
		return fmt.Errorf("service endpoints adapter is required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return err
	}

	endpointType, authScheme, authParams := buildEndpointAuth(secret)

	type projectRef struct {
		ProjectReference struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"projectReference"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	ref := projectRef{Name: secret.Name, Description: ""}
	ref.ProjectReference.ID = projectID
	ref.ProjectReference.Name = project

	type endpointBody struct {
		ID                                string      `json:"id,omitempty"`
		Name                              string      `json:"name"`
		Type                              string      `json:"type"`
		URL                               string      `json:"url"`
		Data                              interface{} `json:"data,omitempty"`
		Authorization                     interface{} `json:"authorization"`
		ServiceEndpointProjectReferences  []projectRef `json:"serviceEndpointProjectReferences"`
	}

	body := endpointBody{
		Name: secret.Name,
		Type: endpointType,
		URL:  secret.URL,
		Authorization: map[string]interface{}{
			"scheme":     authScheme,
			"parameters": authParams,
		},
		ServiceEndpointProjectReferences: []projectRef{ref},
	}
	if endpointType == "dockerregistry" {
		body.Data = map[string]string{"registrytype": "Others"}
	}

	// Check if the endpoint already exists.
	existing, err := s.findEndpointByName(ctx, project, secret.Name)
	if err != nil {
		return fmt.Errorf("lookup service connection %q: %w", secret.Name, err)
	}

	var endpointID string
	forceOverwrite := strings.EqualFold(secret.Overwrite, "true")
	if existing != "" && !forceOverwrite {
		// Already exists and overwrite not requested — skip create/update, only sync grant_access.
		endpointID = existing
	} else if existing != "" {
		// Update: PUT with id in both URL path and body.
		body.ID = existing
		if err := s.serviceEndpoints.Do(ctx, azure.Request{
			Project: project,
			Method:  http.MethodPut,
			Path:    "endpoints/" + existing,
			Body:    body,
		}, nil); err != nil {
			return fmt.Errorf("update service connection %q: %w", secret.Name, err)
		}
		endpointID = existing
	} else {
		// Create: POST without id.
		var created struct {
			ID string `json:"id"`
		}
		if err := s.serviceEndpoints.Do(ctx, azure.Request{
			Project: project,
			Method:  http.MethodPost,
			Path:    "endpoints",
			Body:    body,
		}, &created); err != nil {
			return fmt.Errorf("create service connection %q: %w", secret.Name, err)
		}
		endpointID = created.ID
	}

	// Set grant_access (pipeline permissions) via the PipelinePerms adapter.
	if s.pipelinePerms != nil {
		type allPipelines struct {
			Authorized bool `json:"authorized"`
		}
		type permPayload struct {
			AllPipelines allPipelines `json:"allPipelines"`
		}
		if err := s.pipelinePerms.Do(ctx, azure.Request{
			Project: project,
			Method:  http.MethodPatch,
			Path:    "endpoint/" + endpointID,
			Body:    permPayload{AllPipelines: allPipelines{Authorized: secret.GrantAccess}},
		}, nil); err != nil {
			return fmt.Errorf("set grant_access for service connection %q: %w", secret.Name, err)
		}
	}

	// Assign User role per-endpoint to all groups that hold Creator at project level.
	// Creator means "can create connections" but not "can use them" — explicitly granting
	// User on each endpoint lets Creator groups actually consume the connection in pipelines.
	if err := s.assignCreatorsAsUsersOnEndpoint(ctx, project, projectID, endpointID); err != nil {
		return fmt.Errorf("set per-endpoint user roles for %q: %w", secret.Name, err)
	}
	return nil
}

// assignCreatorsAsUsersOnEndpoint reads the project-level role assignments and assigns
// User role on the specific endpoint to every group that has the Creator role at project level.
// This allows Creator groups to use (not just create) the service connection.
func (s *AzureServiceConnectionService) assignCreatorsAsUsersOnEndpoint(ctx context.Context, project, projectID, endpointID string) error {
	if s.securityRoles == nil {
		return nil
	}
	// Read project-level role assignments.
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
		Path:       fmt.Sprintf("scopes/%s/roleassignments/resources/%s", serviceEndpointRoleScope, projectID),
		APIVersion: "5.0-preview.1",
	}, &resp); err != nil {
		return fmt.Errorf("read project-level service connection roles: %w", err)
	}

	type roleEntry struct {
		UserID   string `json:"userId"`
		RoleName string `json:"roleName"`
	}
	var entries []roleEntry
	for _, r := range resp.Value {
		if r.Access != "assigned" {
			continue
		}
		if r.Role.Name == "Creator" {
			entries = append(entries, roleEntry{UserID: r.Identity.ID, RoleName: "User"})
		}
	}
	if len(entries) == 0 {
		return nil
	}

	resource := projectID + "_" + endpointID
	if err := s.securityRoles.Do(ctx, azure.Request{
		Path:       fmt.Sprintf("scopes/%s/roleassignments/resources/%s", serviceEndpointRoleScope, resource),
		Method:     http.MethodPut,
		APIVersion: "5.0-preview.1",
		Body:       entries,
	}, nil); err != nil {
		return fmt.Errorf("assign User role on endpoint %s: %w", endpointID, err)
	}
	return nil
}

// findEndpointByName looks up the ID of an existing service endpoint by name.
// Returns empty string if not found.
func (s *AzureServiceConnectionService) findEndpointByName(ctx context.Context, project, name string) (string, error) {
	var resp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := s.serviceEndpoints.Do(ctx, azure.Request{
		Project: project,
		Path:    "endpoints",
	}, &resp); err != nil {
		return "", err
	}
	for _, e := range resp.Value {
		if strings.EqualFold(e.Name, name) {
			return e.ID, nil
		}
	}
	return "", nil
}

// buildEndpointAuth maps secret config fields to the Azure DevOps endpoint type,
// auth scheme, and parameters for each supported connection type.
func buildEndpointAuth(secret config.ServiceConnectionSecret) (endpointType, scheme string, params map[string]string) {
	switch strings.ToLower(secret.Type) {
	case "docker registry", "dockerregistry":
		return "dockerregistry", "UsernamePassword", map[string]string{
			"username": secret.User,
			"password": secret.Password,
			"email":    "",
		}
	case "nuget":
		if strings.EqualFold(secret.Auth, "ApiKey") {
			return "externalnugetfeed", "Token", map[string]string{"apitoken": secret.APIKey}
		}
		return "externalnugetfeed", "UsernamePassword", map[string]string{
			"username": secret.User,
			"password": secret.Password,
		}
	case "npm":
		if strings.EqualFold(secret.Auth, "token") {
			return "externalnpmregistry", "Token", map[string]string{"apitoken": secret.Token}
		}
		return "externalnpmregistry", "UsernamePassword", map[string]string{
			"username": secret.User,
			"password": secret.Password,
		}
	case "sonarqube", "sonarqubeconnection":
		// SonarQube only supports UsernamePassword scheme on AzDO Server 2022.2.
		// When auth is "token", the token value goes in the password field.
		// AzDO requires a non-empty username, so fall back to "token" as the username.
		user := secret.User
		pwd := secret.Password
		if strings.EqualFold(secret.Auth, "token") && secret.Token != "" {
			pwd = secret.Token
		}
		if strings.TrimSpace(user) == "" {
			user = "token"
		}
		return "sonarqube", "UsernamePassword", map[string]string{
			"username": user,
			"password": pwd,
		}
	default:
		// Generic and any unknown type: UsernamePassword
		return "generic", "UsernamePassword", map[string]string{
			"username": secret.User,
			"password": secret.Password,
		}
	}
}

// ReadServiceConnectionRoles reads current role assignments for the project-level
// service connection resource, keyed by group descriptor.
func (s *AzureServiceConnectionService) ReadServiceConnectionRoles(ctx context.Context, project string) (map[string]config.Role, error) {
	if s == nil || s.securityRoles == nil {
		return nil, fmt.Errorf("security roles adapter is required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return nil, err
	}

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
		Path:       fmt.Sprintf("scopes/%s/roleassignments/resources/%s", serviceEndpointRoleScope, projectID),
		APIVersion: "5.0-preview.1",
	}, &resp); err != nil {
		return nil, fmt.Errorf("read service connection roles: %w", err)
	}

	// Build TFID → descriptor map from the group directory.
	allGroups, err := s.groups.ListGroups(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("list groups for service connection role mapping: %w", err)
	}
	tfidToDescriptor := make(map[string]string, len(allGroups))
	for _, g := range allGroups {
		tfidToDescriptor[g.TFID] = g.Descriptor
	}

	result := make(map[string]config.Role, len(resp.Value))
	for _, r := range resp.Value {
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

// SetServiceConnectionRoles applies role assignments for the project-level service connection resource.
func (s *AzureServiceConnectionService) SetServiceConnectionRoles(ctx context.Context, project string, changes []permissions.RoleChange) error {
	if s == nil || s.securityRoles == nil {
		return fmt.Errorf("security roles adapter is required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return err
	}

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
		Path:       fmt.Sprintf("scopes/%s/roleassignments/resources/%s", serviceEndpointRoleScope, projectID),
		Method:     http.MethodPut,
		APIVersion: "5.0-preview.1",
		Body:       entries,
	}, nil); err != nil {
		return fmt.Errorf("set service connection roles: %w", err)
	}
	return nil
}

// ReadEndpointRoles reads the per-endpoint role assignments keyed by group descriptor.
// resource = {projectId}_{endpointId}
func (s *AzureServiceConnectionService) ReadEndpointRoles(ctx context.Context, project, endpointID string) (map[string]config.Role, error) {
	if s == nil || s.securityRoles == nil {
		return nil, fmt.Errorf("security roles adapter is required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return nil, err
	}
	resource := projectID + "_" + endpointID

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
		Path:       fmt.Sprintf("scopes/%s/roleassignments/resources/%s", serviceEndpointRoleScope, resource),
		APIVersion: "5.0-preview.1",
	}, &resp); err != nil {
		return nil, fmt.Errorf("read endpoint roles for %s: %w", endpointID, err)
	}

	allGroups, err := s.groups.ListGroups(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("list groups for endpoint role mapping: %w", err)
	}
	tfidToDescriptor := make(map[string]string, len(allGroups))
	for _, g := range allGroups {
		tfidToDescriptor[g.TFID] = g.Descriptor
	}

	result := make(map[string]config.Role, len(resp.Value))
	for _, r := range resp.Value {
		// Include both assigned and inherited — inherited roles from project level satisfy
		// the per-endpoint desired state just as well as explicitly assigned ones.
		if r.Access != "assigned" && r.Access != "inherited" {
			continue
		}
		descriptor, ok := tfidToDescriptor[r.Identity.ID]
		if !ok {
			descriptor = r.Identity.ID
		}
		// assigned takes precedence over inherited
		if _, exists := result[descriptor]; !exists {
			result[descriptor] = config.Role(r.Role.Name)
		}
	}
	return result, nil
}

// SetEndpointRoles assigns roles on a specific endpoint resource.
func (s *AzureServiceConnectionService) SetEndpointRoles(ctx context.Context, project, endpointID string, changes []permissions.RoleChange) error {
	if s == nil || s.securityRoles == nil {
		return fmt.Errorf("security roles adapter is required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return err
	}
	resource := projectID + "_" + endpointID

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
		Path:       fmt.Sprintf("scopes/%s/roleassignments/resources/%s", serviceEndpointRoleScope, resource),
		Method:     http.MethodPut,
		APIVersion: "5.0-preview.1",
		Body:       entries,
	}, nil); err != nil {
		return fmt.Errorf("set endpoint roles for %s: %w", endpointID, err)
	}
	return nil
}
