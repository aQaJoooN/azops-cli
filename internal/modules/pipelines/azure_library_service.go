package pipelines

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/modules/permissions"
)

// libraryNamespaceID is the Library security namespace (confirmed on Server 2022.2).
// Token format: Library/{projectId} — applies to all variable groups in the project.
//
// Bit mapping confirmed from /_apis/securitynamespaces:
//
//	View=1, Administer=2, Create=4, ViewSecrets=8, Use=16, Owner=32
//
// Role → allow bits:
//
//	Administrator = 63  (View+Administer+Create+ViewSecrets+Use+Owner)
//	Creator       = 5   (View+Create)
//	User          = 17  (View+Use)
//	Reader        = 1   (View)
const libraryNamespaceID = "b7e84409-6553-448a-bbb2-af228e07cbeb"

// libraryRoleAllowBits maps config roles to their allow-bit values in the Library namespace.
var libraryRoleAllowBits = map[config.Role]int{
	config.RoleAdministrator: 63, // View+Administer+Create+ViewSecrets+Use+Owner
	config.RoleCreator:       5,  // View+Create
	config.RoleUser:          17, // View+Use
	config.RoleReader:        1,  // View
}

// AzureLibraryService implements the roles portion of LibraryService using the
// Library ACL security namespace (b7e84409-6553-448a-bbb2-af228e07cbeb).
// This is the same namespace the Azure DevOps UI reads and writes.
//
// The create portion (ListVariableGroups / UpsertVariableGroup) requires secrets
// and returns unsupported — the Plan layer skips those calls when
// config.Pipelines.Library.Create is empty.
type AzureLibraryService struct {
	securityACL     *azure.Adapter
	projects        *azure.Adapter
	distributedTask *azure.Adapter
	pipelinePerms   *azure.Adapter
	groups          permissions.GroupDirectory
}

// NewAzureLibraryService creates an AzureLibraryService wired to the given Azure services.
func NewAzureLibraryService(services azure.Services, groups permissions.GroupDirectory) *AzureLibraryService {
	return &AzureLibraryService{
		securityACL:     services.SecurityACL,
		projects:        services.Projects,
		distributedTask: services.DistributedTask,
		pipelinePerms:   services.PipelinePerms,
		groups:          groups,
	}
}

func (s *AzureLibraryService) resolveProjectID(ctx context.Context, project string) (string, error) {
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

// ReadLibraryRoles reads current project-wide library role assignments from the
// Library ACL namespace, keyed by group descriptor.
func (s *AzureLibraryService) ReadLibraryRoles(ctx context.Context, project string) (map[string]config.Role, error) {
	if s == nil || s.securityACL == nil {
		return nil, fmt.Errorf("Azure library service adapters are required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return nil, err
	}
	token := "Library/" + projectID

	var aclResp struct {
		Value []struct {
			AcesDictionary map[string]struct {
				Allow int `json:"allow"`
				Deny  int `json:"deny"`
			} `json:"acesDictionary"`
		} `json:"value"`
	}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "accesscontrollists/" + libraryNamespaceID,
		SkipAPIVersion: true,
		Query:          url.Values{"token": {token}},
	}, &aclResp); err != nil {
		return nil, fmt.Errorf("read library ACL: %w", err)
	}

	// Build a set of known project group descriptors so we only return entries
	// for groups that belong to this project, filtering out system/inherited groups.
	knownGroups, err := s.groups.ListGroups(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("list groups for library role read: %w", err)
	}
	knownDescriptors := make(map[string]struct{}, len(knownGroups))
	for _, g := range knownGroups {
		knownDescriptors[g.Descriptor] = struct{}{}
	}

	result := make(map[string]config.Role)
	for _, acl := range aclResp.Value {
		for descriptor, ace := range acl.AcesDictionary {
			if _, known := knownDescriptors[descriptor]; !known {
				continue
			}
			result[descriptor] = libraryAllowBitsToRole(ace.Allow)
		}
	}
	return result, nil
}

// SetLibraryRoles writes project-wide library role assignments to the
// Library ACL namespace via POST AccessControlEntries.
func (s *AzureLibraryService) SetLibraryRoles(ctx context.Context, project string, changes []permissions.RoleChange) error {
	if s == nil || s.securityACL == nil {
		return fmt.Errorf("Azure library service adapters are required")
	}
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return err
	}
	token := "Library/" + projectID

	type aceEntry struct {
		Descriptor string `json:"descriptor"`
		Allow      int    `json:"allow"`
		Deny       int    `json:"deny"`
	}
	type aclPayload struct {
		Token                string     `json:"token"`
		Merge                bool       `json:"merge"`
		AccessControlEntries []aceEntry `json:"accessControlEntries"`
	}

	entries := make([]aceEntry, 0, len(changes))
	for _, change := range changes {
		allowBits, ok := libraryRoleAllowBits[change.Desired]
		if !ok {
			return fmt.Errorf("unsupported library role %q", change.Desired)
		}
		entries = append(entries, aceEntry{
			Descriptor: change.Principal.Descriptor,
			Allow:      allowBits,
			Deny:       0,
		})
	}

	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "AccessControlEntries/" + libraryNamespaceID,
		Method:         http.MethodPost,
		SkipAPIVersion: true,
		Body:           aclPayload{Token: token, Merge: false, AccessControlEntries: entries},
	}, nil); err != nil {
		return fmt.Errorf("set library permissions: %w", err)
	}
	return nil
}

// libraryAllowBitsToRole maps Library namespace allow bits back to a config.Role.
func libraryAllowBitsToRole(allow int) config.Role {
	switch {
	case allow&2 != 0: // Administer bit set → Administrator
		return config.RoleAdministrator
	case allow&4 != 0 && allow&16 == 0: // Create but not Use → Creator
		return config.RoleCreator
	case allow&16 != 0: // Use bit set → User
		return config.RoleUser
	default:
		return config.RoleReader
	}
}

// ListVariableGroups fetches all variable groups in the project using the DistributedTask API.
func (s *AzureLibraryService) ListVariableGroups(ctx context.Context, project string) ([]VariableGroup, error) {
	if s == nil || s.distributedTask == nil {
		return nil, fmt.Errorf("Azure library service adapters are required")
	}

	var resp struct {
		Value []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Variables map[string]struct {
				Value    string `json:"value"`
				IsSecret bool   `json:"isSecret"`
			} `json:"variables"`
		} `json:"value"`
		Count int `json:"count"`
	}
	if err := s.distributedTask.Do(ctx, azure.Request{
		Project: project,
		Path:    "variablegroups",
	}, &resp); err != nil {
		return nil, fmt.Errorf("list variable groups: %w", err)
	}

	// For each group, fetch pipeline permissions (open/restrict) via the pipelines resource API.
	groups := make([]VariableGroup, 0, len(resp.Value))
	for _, v := range resp.Value {
		vars := make(map[string]VariableGroupVariable, len(v.Variables))
		for name, vv := range v.Variables {
			vars[name] = VariableGroupVariable{Value: vv.Value, IsSecret: vv.IsSecret}
		}
		pp, err := s.readPipelinePermissions(ctx, project, v.ID)
		if err != nil {
			pp = "restrict" // default on error
		}
		groups = append(groups, VariableGroup{Name: v.Name, PipelinePermissions: pp, Variables: vars})
	}
	return groups, nil
}

// readPipelinePermissions checks whether the variable group has open or restricted pipeline access.
func (s *AzureLibraryService) readPipelinePermissions(ctx context.Context, project string, groupID int) (string, error) {
	var resp struct {
		AllPipelines *struct {
			Authorized bool `json:"authorized"`
		} `json:"allPipelines"`
	}
	if err := s.pipelinePerms.Do(ctx, azure.Request{
		Project: project,
		Path:    fmt.Sprintf("variablegroup/%d", groupID),
	}, &resp); err != nil {
		return "restrict", fmt.Errorf("read pipeline permissions for group %d: %w", groupID, err)
	}
	if resp.AllPipelines != nil && resp.AllPipelines.Authorized {
		return "open", nil
	}
	return "restrict", nil
}

// UpsertVariableGroup creates or updates a variable group and sets its pipeline permissions.
func (s *AzureLibraryService) UpsertVariableGroup(ctx context.Context, project string, secret config.VariableGroupSecret) error {
	if s == nil || s.distributedTask == nil {
		return fmt.Errorf("Azure library service adapters are required")
	}

	type varEntry struct {
		Value    string `json:"value"`
		IsSecret bool   `json:"isSecret"`
	}
	type projectRef struct {
		ProjectReference struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"projectReference"`
		Name string `json:"name"`
	}
	type groupPayload struct {
		Name                          string               `json:"name"`
		Type                          string               `json:"type"`
		Variables                     map[string]varEntry  `json:"variables"`
		VariableGroupProjectReferences []projectRef        `json:"variableGroupProjectReferences"`
	}

	// Resolve the project ID for the project reference.
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return fmt.Errorf("resolve project for variable group upsert: %w", err)
	}

	variables := make(map[string]varEntry, len(secret.Variables))
	for _, v := range secret.Variables {
		variables[v.Name] = varEntry{
			Value:    v.Value,
			IsSecret: v.IsSecret == "true",
		}
	}
	ref := projectRef{Name: secret.Name}
	ref.ProjectReference.ID = projectID
	ref.ProjectReference.Name = project
	body := groupPayload{
		Name:      secret.Name,
		Type:      "Vsts",
		Variables: variables,
		VariableGroupProjectReferences: []projectRef{ref},
	}

	// Check if the group already exists to decide create vs update.
	var listResp struct {
		Value []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := s.distributedTask.Do(ctx, azure.Request{
		Project: project,
		Path:    "variablegroups",
		Query:   url.Values{"groupName": {secret.Name}},
	}, &listResp); err != nil {
		return fmt.Errorf("lookup variable group %q: %w", secret.Name, err)
	}

	var groupID int
	if len(listResp.Value) > 0 {
		// Update existing group.
		groupID = listResp.Value[0].ID
		var result struct{ ID int `json:"id"` }
		if err := s.distributedTask.Do(ctx, azure.Request{
			Project: project,
			Method:  "PUT",
			Path:    fmt.Sprintf("variablegroups/%d", groupID),
			Body:    body,
		}, &result); err != nil {
			return fmt.Errorf("update variable group %q: %w", secret.Name, err)
		}
	} else {
		// Create new group.
		var result struct{ ID int `json:"id"` }
		if err := s.distributedTask.Do(ctx, azure.Request{
			Project: project,
			Method:  "POST",
			Path:    "variablegroups",
			Body:    body,
		}, &result); err != nil {
			return fmt.Errorf("create variable group %q: %w", secret.Name, err)
		}
		groupID = result.ID
	}

	// Set pipeline permissions.
	open := pipelinePermissions(secret) == "open"
	type allPipelinesEntry struct {
		Authorized bool `json:"authorized"`
	}
	type permPayload struct {
		AllPipelines allPipelinesEntry `json:"allPipelines"`
	}
	if err := s.pipelinePerms.Do(ctx, azure.Request{
		Project: project,
		Method:  "PATCH",
		Path:    fmt.Sprintf("variablegroup/%d", groupID),
		Body:    permPayload{AllPipelines: allPipelinesEntry{Authorized: open}},
	}, nil); err != nil {
		return fmt.Errorf("set pipeline permissions for group %q: %w", secret.Name, err)
	}
	return nil
}
