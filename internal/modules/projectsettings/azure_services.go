package projectsettings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/modules/permissions"
)

// AzureSecurityService implements supported project security REST operations.
type AzureSecurityService struct {
	groups          permissions.GroupDirectory
	projectIdentity *azure.Adapter
	projectSecurity *azure.Adapter
	permInfo map[string]map[string]displayPermission // project → normalizedName → displayPermission
}

func NewAzureSecurityService(services azure.Services, groups permissions.GroupDirectory) *AzureSecurityService {
	return &AzureSecurityService{groups: groups, projectIdentity: services.ProjectIdentity, projectSecurity: services.ProjectSecurity, permInfo: make(map[string]map[string]displayPermission)}
}
func (s *AzureSecurityService) ListGroups(ctx context.Context, project string) ([]permissions.Group, error) {
	if s == nil || s.groups == nil {
		return nil, fmt.Errorf("Azure security group directory is required")
	}
	return s.groups.ListGroups(ctx, project)
}
func (s *AzureSecurityService) Invalidate(project string) {
	if s == nil || s.groups == nil {
		return
	}
	if inv, ok := s.groups.(permissions.GroupCacheInvalidator); ok {
		inv.Invalidate(project)
	}
}
func (s *AzureSecurityService) CreateGroup(ctx context.Context, project, name string) (permissions.Group, error) {
	if s == nil || s.projectIdentity == nil {
		return permissions.Group{}, fmt.Errorf("Azure project identity adapter is required")
	}
	query := url.Values{"__v": {"5"}}
	body := map[string]string{"name": name, "description": "", "tfid": ""}
	if err := s.projectIdentity.Do(ctx, azure.Request{Project: project, Method: http.MethodPost, Path: "ManageGroup", Query: query, Body: body}, nil); err != nil {
		return permissions.Group{}, err
	}
	groups, err := permissions.NewAzureGroupDirectory(s.projectIdentity).ListGroups(ctx, project)
	if err != nil {
		return permissions.Group{}, err
	}
	for _, group := range groups {
		if group.Name == name {
			return group, nil
		}
	}
	return permissions.Group{}, fmt.Errorf("created group %q was not returned by Azure DevOps", name)
}
// displayPermission is one entry from the _identity/Display permissions array.
type displayPermission struct {
	DisplayName     string `json:"displayName"`
	PermissionBit   int    `json:"permissionBit"`
	PermissionToken string `json:"permissionToken"`
	NamespaceID     string `json:"namespaceId"`
	// PermissionId is the current state: 1=Allow, 2=Deny, 3=NotSet
	PermissionID int `json:"permissionId"`
}

// displayResponse is the shape returned by _api/_identity/Display.
type displayResponse struct {
	Security struct {
		DescriptorIdentityType string              `json:"descriptorIdentityType"`
		DescriptorIdentifier   string              `json:"descriptorIdentifier"`
		Permissions            []displayPermission `json:"permissions"`
	} `json:"security"`
}

// permissionIDToAccessValue maps Azure DevOps permissionId integers to config.AccessValue.
func permissionIDToAccessValue(id int) config.AccessValue {
	switch id {
	case 1:
		return config.AccessAllow
	case 2:
		return config.AccessDeny
	default:
		return config.AccessNotSet
	}
}

// ReadProjectAccess reads the project-level permission bit map and current ACL
// using the internal _api/_identity/Display endpoint — the same one used by
// the Python apply_default_groups.py reference implementation.
func (s *AzureSecurityService) ReadProjectAccess(ctx context.Context, project string) (AccessSnapshot, error) {
	if s == nil || s.projectIdentity == nil {
		return AccessSnapshot{}, fmt.Errorf("Azure project identity adapter is required")
	}

	// 1. List groups to find at least one group whose Display call gives us the permission bit map.
	groups, err := s.ListGroups(ctx, project)
	if err != nil {
		return AccessSnapshot{}, fmt.Errorf("list groups for permission bit map: %w", err)
	}
	if len(groups) == 0 {
		return AccessSnapshot{}, fmt.Errorf("no groups found in project %q", project)
	}

	// 2. Build the bit map and full entry map from the first group's Display response.
	//    Permission names are unique even when bits overlap across namespaces.
	bits := make(map[config.PermissionName]permissions.AccessBit)
	permEntries := make(map[config.PermissionName]displayPermission)
	{
		var display displayResponse
		q := url.Values{"__v": {"5"}, "tfid": {groups[0].TFID}}
		if err := s.projectIdentity.Do(ctx, azure.Request{Project: project, Path: "Display", Query: q}, &display); err != nil {
			return AccessSnapshot{}, fmt.Errorf("read permission bit map: %w", err)
		}
		for _, p := range display.Security.Permissions {
			if p.DisplayName == "" || p.PermissionBit == 0 {
				continue
			}
			name := config.PermissionName(normalizePermissionName(p.DisplayName))
			if _, exists := bits[name]; !exists {
				bits[name] = permissions.MakeAccessBit(p.NamespaceID, p.PermissionBit)
				permEntries[name] = p
			}
		}
	}

	// 3. Read current access values for every group.
	//    Key by descriptor → permissionName → AccessValue (not by bit, since bits can collide across namespaces).
	//    Then convert to the bit-keyed map that PlanAccess expects, using our permEntries for the authoritative bit per name.
	values := make(map[string]map[permissions.AccessBit]config.AccessValue, len(groups))
	for _, group := range groups {
		var display displayResponse
		q := url.Values{"__v": {"5"}, "tfid": {group.TFID}}
		if err := s.projectIdentity.Do(ctx, azure.Request{Project: project, Path: "Display", Query: q}, &display); err != nil {
			return AccessSnapshot{}, fmt.Errorf("read permissions for group %q: %w", group.Name, err)
		}
		perGroup := make(map[permissions.AccessBit]config.AccessValue, len(permEntries))
		for _, p := range display.Security.Permissions {
			if p.DisplayName == "" || p.PermissionBit == 0 {
				continue
			}
			name := config.PermissionName(normalizePermissionName(p.DisplayName))
			canonicalBit, ok := bits[name]
			if !ok {
				continue
			}
			perGroup[canonicalBit] = permissionIDToAccessValue(p.PermissionID)
		}
		values[group.Descriptor] = perGroup
	}

	// Cache permEntries on the service for use by SetProjectAccess.
	s.permInfo[project] = make(map[string]displayPermission, len(permEntries))
	for name, entry := range permEntries {
		s.permInfo[project][string(name)] = entry
	}

	return AccessSnapshot{Bits: bits, Values: values, PermEntries: permEntries}, nil
}

// managePermissionsUpdate is the JSON payload for _security/ManagePermissions.
type managePermissionsUpdate struct {
	IsRemovingIdentity     bool                          `json:"IsRemovingIdentity"`
	TeamFoundationID       string                        `json:"TeamFoundationId"`
	DescriptorIdentityType string                        `json:"DescriptorIdentityType"`
	DescriptorIdentifier   string                        `json:"DescriptorIdentifier"`
	PermissionSetID        string                        `json:"PermissionSetId"`
	PermissionSetToken     string                        `json:"PermissionSetToken"`
	RefreshIdentities      bool                          `json:"RefreshIdentities"`
	Updates                []managePermissionsUpdateItem `json:"Updates"`
	TokenDisplayName       *string                       `json:"TokenDisplayName"`
}

type managePermissionsUpdateItem struct {
	PermissionID  int    `json:"PermissionId"`
	PermissionBit int    `json:"PermissionBit"`
	NamespaceID   string `json:"NamespaceId"`
	Token         string `json:"Token"`
}

// SetProjectAccess applies project-level permission changes using the internal
// _api/_security/ManagePermissions endpoint — identical to what apply_default_groups.py does.
func (s *AzureSecurityService) SetProjectAccess(ctx context.Context, project string, changes []permissions.AccessChange) error {
	if s == nil || s.projectIdentity == nil {
		return fmt.Errorf("Azure project identity adapter is required")
	}

	// Use a fresh (uncached) directory so newly created groups are included.
	freshGroups, err := permissions.NewAzureGroupDirectory(s.projectIdentity).ListGroups(ctx, project)
	if err != nil {
		return fmt.Errorf("list groups for permission update: %w", err)
	}
	tfidByDescriptor := make(map[string]string, len(freshGroups))
	for _, g := range freshGroups {
		tfidByDescriptor[g.Descriptor] = g.TFID
	}

	// Load cached permEntries so we can look up token/namespaceId by permission name.
	cachedEntries := s.permInfo[project]

	// Group changes by principal so we send one request per group.
	byDescriptor := make(map[string][]permissions.AccessChange)
	for _, change := range changes {
		byDescriptor[change.Principal.Descriptor] = append(byDescriptor[change.Principal.Descriptor], change)
	}

	for descriptor, groupChanges := range byDescriptor {
		tfid, ok := tfidByDescriptor[descriptor]
		if !ok {
			return fmt.Errorf("no TFID found for descriptor %q", descriptor)
		}

		// Fetch Display for this group to get PermissionSetId/Token and per-permission metadata.
		// If we have cached entries use them; otherwise fetch fresh.
		var bitInfo map[int]displayPermission
		var permSetID, permSetToken string

		if cachedEntries != nil {
			// Build bitInfo from cached entries
			bitInfo = make(map[int]displayPermission, len(cachedEntries))
			for _, entry := range cachedEntries {
				bitInfo[entry.PermissionBit] = entry
				if permSetToken == "" && strings.HasPrefix(entry.PermissionToken, "$PROJECT:") {
					permSetID = entry.NamespaceID
					tok := strings.TrimPrefix(entry.PermissionToken, "$PROJECT:")
					tok = strings.TrimRight(tok, ":")
					permSetToken = tok
				}
			}
		} else {
			var display displayResponse
			q := url.Values{"__v": {"5"}, "tfid": {tfid}}
			if err := s.projectIdentity.Do(ctx, azure.Request{Project: project, Path: "Display", Query: q}, &display); err != nil {
				return fmt.Errorf("read group info for %q: %w", descriptor, err)
			}
			bitInfo = make(map[int]displayPermission, len(display.Security.Permissions))
			for _, p := range display.Security.Permissions {
				bitInfo[p.PermissionBit] = p
				// Pick permSetID and permSetToken from the same $PROJECT: entry.
				if permSetToken == "" && strings.HasPrefix(p.PermissionToken, "$PROJECT:") {
					permSetID = p.NamespaceID
					tok := strings.TrimPrefix(p.PermissionToken, "$PROJECT:")
					tok = strings.TrimRight(tok, ":")
					permSetToken = tok
				}
			}
		}

		// Build update items — each change carries the permission name so we can
		// look up the per-permission token from cachedEntries (more accurate than bit lookup).
		updateItems := make([]managePermissionsUpdateItem, 0, len(groupChanges))
		for _, change := range groupChanges {
			var entryToken string
			var entryNamespaceID string

			// Prefer cached entries (keyed by name) for accurate per-permission token.
			if cachedEntries != nil {
				if entry, ok := cachedEntries[string(change.Permission)]; ok {
					entryToken = entry.PermissionToken
					entryNamespaceID = entry.NamespaceID
				}
			}
			// Fall back to bitInfo lookup.
			if entryToken == "" {
				if info, ok := bitInfo[int(change.Bit)]; ok {
					entryToken = info.PermissionToken
					entryNamespaceID = info.NamespaceID
				} else {
					return fmt.Errorf("permission bit %d not found for group %q", change.Bit, change.Principal.Name)
				}
			}

			updateItems = append(updateItems, managePermissionsUpdateItem{
				PermissionID:  accessValueToPermissionID(change.Desired),
				PermissionBit: int(change.Bit.RawBit()),
				NamespaceID:   entryNamespaceID,
				Token:         entryToken,
			})
		}

		descType, descID := splitDescriptor(descriptor)
		pkg := managePermissionsUpdate{
			IsRemovingIdentity:     false,
			TeamFoundationID:       tfid,
			DescriptorIdentityType: descType,
			DescriptorIdentifier:   descID,
			PermissionSetID:        permSetID,
			PermissionSetToken:     permSetToken,
			RefreshIdentities:      false,
			Updates:                updateItems,
			TokenDisplayName:       nil,
		}

		pkgJSON, err := json.Marshal(pkg)
		if err != nil {
			return fmt.Errorf("marshal ManagePermissions payload for %q: %w", descriptor, err)
		}

		payload := map[string]string{"updatePackage": string(pkgJSON)}
		if err := s.projectSecurity.Do(ctx, azure.Request{
			Project: project,
			Method:  http.MethodPost,
			Path:    "ManagePermissions",
			Query:   url.Values{"__v": {"5"}},
			Body:    payload,
		}, nil); err != nil {
			return fmt.Errorf("set permissions for group %q: %w", descriptor, err)
		}
	}
	return nil
}

// accessValueToPermissionID converts a config.AccessValue to the Azure DevOps permissionId integer.
// 1=Allow, 2=Deny, 3=NotSet
func accessValueToPermissionID(v config.AccessValue) int {
	switch v {
	case config.AccessAllow:
		return 1
	case config.AccessDeny:
		return 2
	default:
		return 3
	}
}

// splitDescriptor splits "type;id" into its two components.
func splitDescriptor(descriptor string) (identityType, identifier string) {
	parts := strings.SplitN(descriptor, ";", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return descriptor, ""
}

// normalizePermissionName converts a display name like "View analytics" to the
// config key format "View_analytics" used in config.yaml.
// It also strips trailing punctuation that some Server versions append.
func normalizePermissionName(displayName string) string {
	name := strings.ReplaceAll(displayName, " ", "_")
	name = strings.TrimRight(name, "._-")
	return name
}

type UnsupportedOverviewService struct{}

func (UnsupportedOverviewService) ReadOverview(context.Context, string) (config.OverviewConfig, error) {
	return config.OverviewConfig{}, azure.Unsupported(azure.Projects, "read project feature states")
}
func (UnsupportedOverviewService) SetOverview(context.Context, string, config.OverviewConfig) error {
	return azure.Unsupported(azure.Projects, "set project feature states")
}

// repoNamespaceID is the fixed Azure DevOps Git repository security namespace ID.
const repoNamespaceID = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

// repoPermissionBits maps config.yaml permission names to the confirmed repository namespace bits.
var repoPermissionBits = map[config.PermissionName]permissions.AccessBit{
	"Administer":                                      permissions.MakeAccessBit(repoNamespaceID, 1),
	"Read":                                            permissions.MakeAccessBit(repoNamespaceID, 2),
	"Contribute":                                      permissions.MakeAccessBit(repoNamespaceID, 4),
	"Force_push":                                      permissions.MakeAccessBit(repoNamespaceID, 8),
	"Create_branch":                                   permissions.MakeAccessBit(repoNamespaceID, 16),
	"Create_tag":                                      permissions.MakeAccessBit(repoNamespaceID, 32),
	"Manage_notes":                                    permissions.MakeAccessBit(repoNamespaceID, 64),
	"Bypass_policies_when_completing_pull_requests":   permissions.MakeAccessBit(repoNamespaceID, 32768),
	"Bypass_policies_when_pushing":                    permissions.MakeAccessBit(repoNamespaceID, 128),
	"Create_repository":                               permissions.MakeAccessBit(repoNamespaceID, 256),
	"Delete_or_disable_repository":                    permissions.MakeAccessBit(repoNamespaceID, 512),
	"Rename_repository":                               permissions.MakeAccessBit(repoNamespaceID, 1024),
	"Edit_policies":                                   permissions.MakeAccessBit(repoNamespaceID, 2048),
	"Remove_others_locks":                             permissions.MakeAccessBit(repoNamespaceID, 4096),
	"Manage_permissions":                              permissions.MakeAccessBit(repoNamespaceID, 8192),
	"Contribute_to_pull_requests":                     permissions.MakeAccessBit(repoNamespaceID, 16384),
}

// fileSizePolicyTypeID is the fixed Azure DevOps policy type for file size restriction.
const fileSizePolicyTypeID = "2e26e725-8201-4edd-8bf5-978563c34a80"

// AzureRepositoryService implements RepositoryService using the confirmed public REST APIs.
type AzureRepositoryService struct {
	projects    *azure.Adapter
	securityACL *azure.Adapter
	policy      *azure.Adapter
}

func NewAzureRepositoryService(services azure.Services) *AzureRepositoryService {
	return &AzureRepositoryService{
		projects:    services.Projects,
		securityACL: services.SecurityACL,
		policy:      services.Policy,
	}
}

// resolveProjectID fetches the project GUID for a given project name.
func (s *AzureRepositoryService) resolveProjectID(ctx context.Context, project string) (string, error) {
	var response struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := s.projects.Do(ctx, azure.Request{Path: "", APIVersion: "7.0"}, &response); err != nil {
		return "", fmt.Errorf("list projects: %w", err)
	}
	for _, p := range response.Value {
		if strings.EqualFold(p.Name, project) {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("project %q not found", project)
}

// ReadRepositoryState reads current repository ACL and file size policy.
func (s *AzureRepositoryService) ReadRepositoryState(ctx context.Context, project string) (RepositoryState, error) {
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return RepositoryState{}, err
	}

	// Read current file size policy (all-repo scope).
	currentFileSize := ""
	if s.policy != nil {
		type policyConfig struct {
			Type struct {
				ID string `json:"id"`
			} `json:"type"`
			Settings struct {
				MaximumGitBlobSizeInBytes int64 `json:"maximumGitBlobSizeInBytes"`
				Scope                     []struct {
					RepositoryID *string `json:"repositoryId"`
				} `json:"scope"`
			} `json:"settings"`
		}
		var listResp struct {
			Value []policyConfig `json:"value"`
		}
		if err := s.policy.Do(ctx, azure.Request{Project: project, Path: "configurations"}, &listResp); err == nil {
			for _, p := range listResp.Value {
				if p.Type.ID != fileSizePolicyTypeID {
					continue
				}
				for _, scope := range p.Settings.Scope {
					if scope.RepositoryID == nil && p.Settings.MaximumGitBlobSizeInBytes > 0 {
						currentFileSize = formatBytesToFileSize(p.Settings.MaximumGitBlobSizeInBytes)
						break
					}
				}
				if currentFileSize != "" {
					break
				}
			}
		}
	}

	token := "repoV2/" + projectID
	var aclResponse struct {
		Value []struct {
			Token          string `json:"token"`
			AcesDictionary map[string]struct {
				Allow int `json:"allow"`
				Deny  int `json:"deny"`
			} `json:"acesDictionary"`
		} `json:"value"`
	}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "accesscontrollists/" + repoNamespaceID,
		SkipAPIVersion: true,
		Query:          url.Values{"token": {token}},
	}, &aclResponse); err != nil {
		return RepositoryState{}, fmt.Errorf("read repository ACL: %w", err)
	}

	// Build values map: descriptor → bit → AccessValue
	values := make(map[string]map[permissions.AccessBit]config.AccessValue)
	for _, acl := range aclResponse.Value {
		for descriptor, ace := range acl.AcesDictionary {
			perDesc := make(map[permissions.AccessBit]config.AccessValue)
			for _, bit := range repoPermissionBits {
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

	return RepositoryState{
		MaximumFileSize: currentFileSize,
		Access: AccessSnapshot{
			Bits:   repoPermissionBits,
			Values: values,
		},
	}, nil
}

// parseFileSizeToBytes converts a human-readable size string like "10 MB" to bytes.
// Supported units: KB, MB, GB (case-insensitive).
func parseFileSizeToBytes(size string) (int64, error) {
	size = strings.TrimSpace(size)
	parts := strings.Fields(size)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid file size format %q, expected e.g. \"10 MB\"", size)
	}
	var value float64
	if _, err := fmt.Sscanf(parts[0], "%f", &value); err != nil {
		return 0, fmt.Errorf("invalid file size number %q", parts[0])
	}
	switch strings.ToUpper(parts[1]) {
	case "KB":
		return int64(value * 1024), nil
	case "MB":
		return int64(value * 1024 * 1024), nil
	case "GB":
		return int64(value * 1024 * 1024 * 1024), nil
	default:
		return 0, fmt.Errorf("unsupported file size unit %q, expected KB, MB, or GB", parts[1])
	}
}

// formatBytesToFileSize converts bytes back to a human-readable string matching config format.
func formatBytesToFileSize(bytes int64) string {
	switch {
	case bytes%(1024*1024*1024) == 0:
		return fmt.Sprintf("%d GB", bytes/(1024*1024*1024))
	case bytes%(1024*1024) == 0:
		return fmt.Sprintf("%d MB", bytes/(1024*1024))
	default:
		return fmt.Sprintf("%d KB", bytes/1024)
	}
}

// SetMaximumFileSize upserts the project-wide file size restriction policy.
func (s *AzureRepositoryService) SetMaximumFileSize(ctx context.Context, project, size string) error {
	if s.policy == nil {
		return fmt.Errorf("policy adapter is required")
	}
	bytes, err := parseFileSizeToBytes(size)
	if err != nil {
		return err
	}

	// Find existing all-repo file size policy (scope repositoryId = null).
	type policyConfig struct {
		ID        int  `json:"id"`
		IsEnabled bool `json:"isEnabled"`
		IsBlocking bool `json:"isBlocking"`
		Type      struct {
			ID string `json:"id"`
		} `json:"type"`
		Settings struct {
			MaximumGitBlobSizeInBytes int64       `json:"maximumGitBlobSizeInBytes"`
			UseUncompressedSize       bool        `json:"useUncompressedSize"`
			Scope                     []struct {
				RepositoryID *string `json:"repositoryId"`
			} `json:"scope"`
		} `json:"settings"`
	}
	var listResp struct {
		Value []policyConfig `json:"value"`
	}
	if err := s.policy.Do(ctx, azure.Request{Project: project, Path: "configurations"}, &listResp); err != nil {
		return fmt.Errorf("list policy configurations: %w", err)
	}

	// Find the all-repo policy (repositoryId == null).
	existingID := 0
	for _, p := range listResp.Value {
		if p.Type.ID != fileSizePolicyTypeID {
			continue
		}
		for _, scope := range p.Settings.Scope {
			if scope.RepositoryID == nil {
				existingID = p.ID
				break
			}
		}
		if existingID != 0 {
			break
		}
	}

	body := map[string]any{
		"isEnabled":  true,
		"isBlocking": true,
		"type":       map[string]string{"id": fileSizePolicyTypeID},
		"settings": map[string]any{
			"maximumGitBlobSizeInBytes": bytes,
			"useUncompressedSize":       false,
			"scope":                     []map[string]any{{"repositoryId": nil}},
		},
	}

	if existingID != 0 {
		// Update existing policy via PUT.
		return s.policy.Do(ctx, azure.Request{
			Project: project,
			Method:  http.MethodPut,
			Path:    fmt.Sprintf("configurations/%d", existingID),
			Body:    body,
		}, nil)
	}
	// Create new policy via POST.
	return s.policy.Do(ctx, azure.Request{
		Project: project,
		Method:  http.MethodPost,
		Path:    "configurations",
		Body:    body,
	}, nil)
}

// SetRepositoryAccess writes ACEs using POST /_apis/AccessControlEntries/{namespaceId}.
func (s *AzureRepositoryService) SetRepositoryAccess(ctx context.Context, project string, changes []permissions.AccessChange) error {
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return err
	}
	token := "repoV2/" + projectID

	// Group changes by descriptor so we merge allow/deny bits per group in one call.
	type ace struct{ allow, deny int }
	byDescriptor := make(map[string]*ace)
	for _, change := range changes {
		a := byDescriptor[change.Principal.Descriptor]
		if a == nil {
			a = &ace{}
			byDescriptor[change.Principal.Descriptor] = a
		}
		raw := int(change.Bit.RawBit())
		// Clear the bit first, then set according to desired value.
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
		Descriptor   string `json:"descriptor"`
		Allow        int    `json:"allow"`
		Deny         int    `json:"deny"`
		ExtendedInfo struct {
			EffectiveAllow int `json:"effectiveAllow"`
			EffectiveDeny  int `json:"effectiveDeny"`
			InheritedAllow int `json:"inheritedAllow"`
			InheritedDeny  int `json:"inheritedDeny"`
		} `json:"extendedInfo"`
	}
	type aclPayload struct {
		Token               string     `json:"token"`
		Merge               bool       `json:"merge"`
		AccessControlEntries []aceEntry `json:"accessControlEntries"`
	}

	// Build one entry per descriptor and POST in a single request.
	entries := make([]aceEntry, 0, len(byDescriptor))
	for descriptor, a := range byDescriptor {
		e := aceEntry{Descriptor: descriptor, Allow: a.allow, Deny: a.deny}
		e.ExtendedInfo.EffectiveAllow = a.allow
		e.ExtendedInfo.EffectiveDeny = a.deny
		e.ExtendedInfo.InheritedAllow = a.allow
		e.ExtendedInfo.InheritedDeny = a.deny
		entries = append(entries, e)
	}

	payload := aclPayload{Token: token, Merge: true, AccessControlEntries: entries}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "AccessControlEntries/" + repoNamespaceID,
		Method:         http.MethodPost,
		SkipAPIVersion: true,
		Body:           payload,
	}, nil); err != nil {
		return fmt.Errorf("set repository permissions: %w", err)
	}
	return nil
}

// AzureSettingsService implements SettingsService using confirmed public REST APIs.
// General toggles: PATCH /{project}/_apis/build/generalsettings?api-version=7.1
// Retention: GET/PATCH /{project}/_apis/build/retention?api-version=7.0
type AzureSettingsService struct {
	build          *azure.Adapter
	buildRetention *azure.Adapter
}

func NewAzureSettingsService(services azure.Services) *AzureSettingsService {
	return &AzureSettingsService{build: services.Build, buildRetention: services.BuildRetention}
}

// generalSettingsResponse maps the confirmed build/generalsettings API response fields.
type generalSettingsResponse struct {
	StatusBadgesArePrivate             bool `json:"statusBadgesArePrivate"`
	EnforceSettableVar                 bool `json:"enforceSettableVar"`
	EnforceJobAuthScope                bool `json:"enforceJobAuthScope"`
	EnforceJobAuthScopeForReleases     bool `json:"enforceJobAuthScopeForReleases"`
	PublishPipelineMetadata            bool `json:"publishPipelineMetadata"`
	EnforceReferencedRepoScopedToken   bool `json:"enforceReferencedRepoScopedToken"`
	DisableClassicBuildPipelineCreation   bool `json:"disableClassicBuildPipelineCreation"`
	DisableClassicReleasePipelineCreation bool `json:"disableClassicReleasePipelineCreation"`
	EnableShellTasksArgsSanitizing     bool `json:"enableShellTasksArgsSanitizing"`
	DisableImpliedYAMLCiTrigger        bool `json:"disableImpliedYAMLCiTrigger"`
}

// retentionResponse maps the confirmed build/retention API response fields.
type retentionResponse struct {
	PurgeArtifacts        *struct{ Value int `json:"value"` } `json:"purgeArtifacts"`
	PurgeRuns             *struct{ Value int `json:"value"` } `json:"purgeRuns"`
	PurgePullRequestRuns  *struct{ Value int `json:"value"` } `json:"purgePullRequestRuns"`
}

func onOffToBool(v config.OnOff) bool { return v == config.On }
func boolToOnOff(v bool) config.OnOff {
	if v {
		return config.On
	}
	return config.Off
}

func (s *AzureSettingsService) ReadPipelineSettings(ctx context.Context, project string) (config.PipelineSettingsConfig, error) {
	if s == nil || s.build == nil {
		return config.PipelineSettingsConfig{}, fmt.Errorf("build adapter is required")
	}
	var g generalSettingsResponse
	if err := s.build.Do(ctx, azure.Request{Project: project, Path: "generalsettings"}, &g); err != nil {
		return config.PipelineSettingsConfig{}, fmt.Errorf("read build generalsettings: %w", err)
	}
	cfg := config.PipelineSettingsConfig{}
	cfg.General.DisableAnonymousBadges = boolToOnOff(g.StatusBadgesArePrivate)
	cfg.General.LimitQueueTimeVariables = boolToOnOff(g.EnforceSettableVar)
	cfg.General.LimitNonReleaseAuthorization = boolToOnOff(g.EnforceJobAuthScope)
	cfg.General.LimitReleaseAuthorization = boolToOnOff(g.EnforceJobAuthScopeForReleases)
	cfg.General.PublishMetadata = boolToOnOff(g.PublishPipelineMetadata)
	cfg.General.ProtectYAMLRepositories = boolToOnOff(g.EnforceReferencedRepoScopedToken)
	cfg.General.DisableClassicBuild = boolToOnOff(g.DisableClassicBuildPipelineCreation)
	cfg.General.DisableClassicRelease = boolToOnOff(g.DisableClassicReleasePipelineCreation)
	cfg.General.EnableShellArgumentValidation = boolToOnOff(g.EnableShellTasksArgsSanitizing)
	cfg.Triggers.DisableImpliedYAMLCI = boolToOnOff(g.DisableImpliedYAMLCiTrigger)
	// RetentionPolicy is intentionally not read — the build/retention PATCH endpoint
	// does not persist on Azure DevOps Server 2022.2 without elevated permissions.
	// RetentionPolicy fields are left at zero so they never trigger a diff.
	return cfg, nil
}

func (s *AzureSettingsService) SetPipelineSettings(ctx context.Context, project string, cfg config.PipelineSettingsConfig) error {
	if s == nil || s.build == nil {
		return fmt.Errorf("build adapter is required")
	}
	generalPayload := map[string]bool{
		"statusBadgesArePrivate":                onOffToBool(cfg.General.DisableAnonymousBadges),
		"enforceSettableVar":                    onOffToBool(cfg.General.LimitQueueTimeVariables),
		"enforceJobAuthScope":                   onOffToBool(cfg.General.LimitNonReleaseAuthorization),
		"enforceJobAuthScopeForReleases":        onOffToBool(cfg.General.LimitReleaseAuthorization),
		"publishPipelineMetadata":               onOffToBool(cfg.General.PublishMetadata),
		"enforceReferencedRepoScopedToken":      onOffToBool(cfg.General.ProtectYAMLRepositories),
		"disableClassicBuildPipelineCreation":   onOffToBool(cfg.General.DisableClassicBuild),
		"disableClassicReleasePipelineCreation": onOffToBool(cfg.General.DisableClassicRelease),
		"enableShellTasksArgsSanitizing":        onOffToBool(cfg.General.EnableShellArgumentValidation),
		"disableImpliedYAMLCiTrigger":           onOffToBool(cfg.Triggers.DisableImpliedYAMLCI),
	}
	return s.build.Do(ctx, azure.Request{
		Project: project,
		Method:  http.MethodPatch,
		Path:    "generalsettings",
		Body:    generalPayload,
	}, nil)
}
