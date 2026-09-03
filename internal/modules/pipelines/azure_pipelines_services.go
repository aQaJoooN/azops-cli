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

// environmentNamespaceID is the Environment security namespace (confirmed on Server 2022.2).
// Token format: Environments/{projectId} (project-level)
// Bit mapping: View=1, Manage=2, ManageHistory=4, Administer=8, Use=16, Create=32
// Role → allow bits: Administrator=63, Creator=33, User=17, Reader=1
const environmentNamespaceID = "83d4c2e6-e57d-4d6e-892b-b87222b7ad20"

// environmentRoleAllowBits maps config roles to their allow bit values in the Environment namespace.
var environmentRoleAllowBits = map[config.Role]int{
	config.RoleAdministrator: 63, // View+Manage+ManageHistory+Administer+Use+Create
	config.RoleCreator:       33, // View+Create
	config.RoleUser:          17, // View+Use
	config.RoleReader:        1,  // View
}

// taskGroupNamespaceID is the MetaTask security namespace for task groups (Server 2022.2).
// Confirmed actions: Administer(1), Edit(2), Delete(4)
// DisplayNames: "Administer task group permissions", "Edit task group", "Delete task group"
const taskGroupNamespaceID = "f6a4de49-dbe2-4704-86dc-f8ec1a294436"

// taskGroupPermissionBits maps config.yaml permission names (display name with spaces→underscores)
// to MetaTask namespace bits, confirmed from /_apis/securitynamespaces on Server 2022.2.
var taskGroupPermissionBits = map[config.PermissionName]permissions.AccessBit{
	"Administer_task_group_permissions": permissions.MakeAccessBit(taskGroupNamespaceID, 1),
	"Edit_task_group":                   permissions.MakeAccessBit(taskGroupNamespaceID, 2),
	"Delete_task_group":                 permissions.MakeAccessBit(taskGroupNamespaceID, 4),
}

// ─── shared helper ───────────────────────────────────────────────────────────

func resolveProjectIDFromProjects(ctx context.Context, projects *azure.Adapter, project string) (string, error) {
	var resp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := projects.Do(ctx, azure.Request{Path: "", APIVersion: "7.0"}, &resp); err != nil {
		return "", fmt.Errorf("list projects: %w", err)
	}
	for _, p := range resp.Value {
		if strings.EqualFold(p.Name, project) {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("project %q not found", project)
}

// ─── AzureEnvironmentService ─────────────────────────────────────────────────

// AzureEnvironmentService implements EnvironmentService using the Environment
// ACL security namespace (83d4c2e6-e57d-4d6e-892b-b87222b7ad20).
// Token: Environments/{projectId} — applies to all environments in the project.
// Roles are translated to allow-bit sets: Administrator=63, Creator=33, User=17, Reader=1.
type AzureEnvironmentService struct {
	securityACL *azure.Adapter
	projects    *azure.Adapter
	groups      permissions.GroupDirectory
}

func NewAzureEnvironmentService(services azure.Services, groups permissions.GroupDirectory) *AzureEnvironmentService {
	return &AzureEnvironmentService{
		securityACL: services.SecurityACL,
		projects:    services.Projects,
		groups:      groups,
	}
}

func (s *AzureEnvironmentService) ReadEnvironmentRoles(ctx context.Context, project string) (map[string]config.Role, error) {
	if s == nil || s.securityACL == nil {
		return nil, fmt.Errorf("Azure environment service adapters are required")
	}
	projectID, err := resolveProjectIDFromProjects(ctx, s.projects, project)
	if err != nil {
		return nil, err
	}
	token := "Environments/" + projectID

	var aclResp struct {
		Value []struct {
			AcesDictionary map[string]struct {
				Descriptor string `json:"descriptor"`
				Allow      int    `json:"allow"`
				Deny       int    `json:"deny"`
			} `json:"acesDictionary"`
		} `json:"value"`
	}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "accesscontrollists/" + environmentNamespaceID,
		SkipAPIVersion: true,
		Query:          url.Values{"token": {token}},
	}, &aclResp); err != nil {
		return nil, fmt.Errorf("read environment ACL: %w", err)
	}

	// Build descriptor→role from current allow bits.
	result := make(map[string]config.Role)
	for _, acl := range aclResp.Value {
		for descriptor, ace := range acl.AcesDictionary {
			result[descriptor] = allowBitsToRole(ace.Allow)
		}
	}
	return result, nil
}

func (s *AzureEnvironmentService) SetEnvironmentRoles(ctx context.Context, project string, changes []permissions.RoleChange) error {
	if s == nil || s.securityACL == nil {
		return fmt.Errorf("Azure environment service adapters are required")
	}
	projectID, err := resolveProjectIDFromProjects(ctx, s.projects, project)
	if err != nil {
		return err
	}
	token := "Environments/" + projectID

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
		allowBits, ok := environmentRoleAllowBits[change.Desired]
		if !ok {
			return fmt.Errorf("unsupported environment role %q", change.Desired)
		}
		entries = append(entries, aceEntry{
			Descriptor: change.Principal.Descriptor,
			Allow:      allowBits,
			Deny:       0,
		})
	}

	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "AccessControlEntries/" + environmentNamespaceID,
		Method:         http.MethodPost,
		SkipAPIVersion: true,
		Body:           aclPayload{Token: token, Merge: true, AccessControlEntries: entries},
	}, nil); err != nil {
		return fmt.Errorf("set environment permissions: %w", err)
	}
	return nil
}

// allowBitsToRole maps Environment namespace allow bits back to a config.Role.
func allowBitsToRole(allow int) config.Role {
	switch allow {
	case 63:
		return config.RoleAdministrator
	case 33:
		return config.RoleCreator
	case 17:
		return config.RoleUser
	default:
		return config.RoleReader
	}
}

// ─── AzureTaskGroupService ────────────────────────────────────────────────────

// AzureTaskGroupService implements TaskGroupService using the MetaTask security ACL namespace.
// Token: {projectId} (project-level, confirmed on Server 2022.2)
type AzureTaskGroupService struct {
	securityACL *azure.Adapter
	projects    *azure.Adapter
}

func NewAzureTaskGroupService(services azure.Services) *AzureTaskGroupService {
	return &AzureTaskGroupService{
		securityACL: services.SecurityACL,
		projects:    services.Projects,
	}
}

func (s *AzureTaskGroupService) ReadTaskGroupAccess(ctx context.Context, project string) (AccessSnapshot, error) {
	if s == nil || s.securityACL == nil {
		return AccessSnapshot{}, fmt.Errorf("Azure task group service adapters are required")
	}
	projectID, err := resolveProjectIDFromProjects(ctx, s.projects, project)
	if err != nil {
		return AccessSnapshot{}, err
	}

	var aclResponse struct {
		Value []struct {
			AcesDictionary map[string]struct {
				Allow int `json:"allow"`
				Deny  int `json:"deny"`
			} `json:"acesDictionary"`
		} `json:"value"`
	}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "accesscontrollists/" + taskGroupNamespaceID,
		SkipAPIVersion: true,
		Query:          url.Values{"token": {projectID}},
	}, &aclResponse); err != nil {
		return AccessSnapshot{}, fmt.Errorf("read task group ACL: %w", err)
	}

	values := make(map[string]map[permissions.AccessBit]config.AccessValue)
	for _, acl := range aclResponse.Value {
		for descriptor, ace := range acl.AcesDictionary {
			perDesc := make(map[permissions.AccessBit]config.AccessValue, len(taskGroupPermissionBits))
			for _, bit := range taskGroupPermissionBits {
				raw := int(bit.RawBit())
				switch {
				case ace.Deny&raw != 0:
					perDesc[bit] = config.AccessDeny
				case ace.Allow&raw != 0:
					perDesc[bit] = config.AccessAllow
				default:
					perDesc[bit] = config.AccessNotSet
				}
			}
			values[descriptor] = perDesc
		}
	}
	return AccessSnapshot{Bits: taskGroupPermissionBits, Values: values}, nil
}

func (s *AzureTaskGroupService) SetTaskGroupAccess(ctx context.Context, project string, changes []permissions.AccessChange) error {
	if s == nil || s.securityACL == nil {
		return fmt.Errorf("Azure task group service adapters are required")
	}
	projectID, err := resolveProjectIDFromProjects(ctx, s.projects, project)
	if err != nil {
		return err
	}

	type ace struct{ allow, deny int }
	byDescriptor := make(map[string]*ace)
	for _, change := range changes {
		a := byDescriptor[change.Principal.Descriptor]
		if a == nil {
			a = &ace{}
			byDescriptor[change.Principal.Descriptor] = a
		}
		raw := int(change.Bit.RawBit())
		a.allow &^= raw
		a.deny &^= raw
		switch change.Desired {
		case config.AccessAllow:
			a.allow |= raw
		case config.AccessDeny:
			a.deny |= raw
		}
	}

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

	entries := make([]aceEntry, 0, len(byDescriptor))
	for descriptor, a := range byDescriptor {
		entries = append(entries, aceEntry{Descriptor: descriptor, Allow: a.allow, Deny: a.deny})
	}

	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "AccessControlEntries/" + taskGroupNamespaceID,
		Method:         http.MethodPost,
		SkipAPIVersion: true,
		Body:           aclPayload{Token: projectID, Merge: true, AccessControlEntries: entries},
	}, nil); err != nil {
		return fmt.Errorf("set task group permissions: %w", err)
	}
	return nil
}

// ─── AzureDeploymentGroupService ─────────────────────────────────────────────

// AzureDeploymentGroupService implements DeploymentGroupService using the
// DistributedTask ACL security namespace (101eae8c-1709-47f9-b228-0e476c35b3ba).
// Token: MachineGroups/{projectId} — project-level default for all deployment groups.
//
// Bit mapping confirmed on Server 2022.2:
//   View=1, Manage=2, Listen=4, AdministerPermissions=8, Use=16, Create=32
//
// Role → allow bits (observed from server, Listen bit excluded from Administrator):
//   Administrator=59 (View+Manage+Administer+Use+Create), Creator=33, User=17, Reader=1
const deploymentGroupNamespaceID = "101eae8c-1709-47f9-b228-0e476c35b3ba"

var deploymentGroupRoleAllowBits = map[config.Role]int{
	config.RoleAdministrator: 59, // View+Manage+AdministerPermissions+Use+Create
	config.RoleCreator:       33, // View+Create
	config.RoleUser:          17, // View+Use
	config.RoleReader:        1,  // View
}

type AzureDeploymentGroupService struct {
	securityACL *azure.Adapter
	projects    *azure.Adapter
}

func NewAzureDeploymentGroupService(services azure.Services) *AzureDeploymentGroupService {
	return &AzureDeploymentGroupService{
		securityACL: services.SecurityACL,
		projects:    services.Projects,
	}
}

func (s *AzureDeploymentGroupService) ReadDeploymentGroupRoles(ctx context.Context, project string) (map[string]config.Role, error) {
	if s == nil || s.securityACL == nil {
		return nil, fmt.Errorf("Azure deployment group service adapters are required")
	}
	projectID, err := resolveProjectIDFromProjects(ctx, s.projects, project)
	if err != nil {
		return nil, err
	}
	token := "MachineGroups/" + projectID

	var aclResp struct {
		Value []struct {
			AcesDictionary map[string]struct {
				Descriptor string `json:"descriptor"`
				Allow      int    `json:"allow"`
				Deny       int    `json:"deny"`
			} `json:"acesDictionary"`
		} `json:"value"`
	}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "accesscontrollists/" + deploymentGroupNamespaceID,
		SkipAPIVersion: true,
		Query:          url.Values{"token": {token}},
	}, &aclResp); err != nil {
		return nil, fmt.Errorf("read deployment group ACL: %w", err)
	}

	result := make(map[string]config.Role)
	for _, acl := range aclResp.Value {
		for descriptor, ace := range acl.AcesDictionary {
			result[descriptor] = deploymentGroupAllowBitsToRole(ace.Allow)
		}
	}
	return result, nil
}

func (s *AzureDeploymentGroupService) SetDeploymentGroupRoles(ctx context.Context, project string, changes []permissions.RoleChange) error {
	if s == nil || s.securityACL == nil {
		return fmt.Errorf("Azure deployment group service adapters are required")
	}
	projectID, err := resolveProjectIDFromProjects(ctx, s.projects, project)
	if err != nil {
		return err
	}
	token := "MachineGroups/" + projectID

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
		allowBits, ok := deploymentGroupRoleAllowBits[change.Desired]
		if !ok {
			return fmt.Errorf("unsupported deployment group role %q", change.Desired)
		}
		entries = append(entries, aceEntry{
			Descriptor: change.Principal.Descriptor,
			Allow:      allowBits,
			Deny:       0,
		})
	}

	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "AccessControlEntries/" + deploymentGroupNamespaceID,
		Method:         http.MethodPost,
		SkipAPIVersion: true,
		Body:           aclPayload{Token: token, Merge: true, AccessControlEntries: entries},
	}, nil); err != nil {
		return fmt.Errorf("set deployment group permissions: %w", err)
	}
	return nil
}

func deploymentGroupAllowBitsToRole(allow int) config.Role {
	switch allow {
	case 59, 63: // 63 = all bits including Listen, treat as Administrator
		return config.RoleAdministrator
	case 33:
		return config.RoleCreator
	case 17:
		return config.RoleUser
	default:
		return config.RoleReader
	}
}
