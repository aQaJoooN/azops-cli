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
	securityACL *azure.Adapter
	projects    *azure.Adapter
	groups      permissions.GroupDirectory
}

// NewAzureLibraryService creates an AzureLibraryService wired to the given Azure services.
func NewAzureLibraryService(services azure.Services, groups permissions.GroupDirectory) *AzureLibraryService {
	return &AzureLibraryService{
		securityACL: services.SecurityACL,
		projects:    services.Projects,
		groups:      groups,
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

// ListVariableGroups is not implemented in the permissions-only path.
func (s *AzureLibraryService) ListVariableGroups(_ context.Context, _ string) ([]VariableGroup, error) {
	return nil, azure.Unsupported(azure.DistributedTask, "list variable groups")
}

// UpsertVariableGroup is not implemented in the permissions-only path.
func (s *AzureLibraryService) UpsertVariableGroup(_ context.Context, _ string, _ config.VariableGroupSecret) error {
	return azure.Unsupported(azure.DistributedTask, "upsert variable group")
}
