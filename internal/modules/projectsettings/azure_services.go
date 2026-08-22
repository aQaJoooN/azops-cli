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
	security        *azure.Adapter
	// permInfo caches the full display permission metadata per project, keyed by
	// normalized permission name. Used by SetProjectAccess to find the right token/namespaceId.
	permInfo map[string]map[string]displayPermission // project → normalizedName → displayPermission
}

func NewAzureSecurityService(services azure.Services, groups permissions.GroupDirectory) *AzureSecurityService {
	return &AzureSecurityService{groups: groups, projectIdentity: services.ProjectIdentity, projectSecurity: services.ProjectSecurity, security: services.Security, permInfo: make(map[string]map[string]displayPermission)}
}
func (s *AzureSecurityService) ListGroups(ctx context.Context, project string) ([]permissions.Group, error) {
	if s == nil || s.groups == nil {
		return nil, fmt.Errorf("Azure security group directory is required")
	}
	return s.groups.ListGroups(ctx, project)
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

// Unsupported adapters explicitly reject project settings without a verified public Server 2022.2 endpoint.
type UnsupportedSettingsService struct{}

func (UnsupportedSettingsService) ReadPipelineSettings(context.Context, string) (config.PipelineSettingsConfig, error) {
	return config.PipelineSettingsConfig{}, azure.Unsupported(azure.Build, "read pipeline project settings")
}
func (UnsupportedSettingsService) SetPipelineSettings(context.Context, string, config.PipelineSettingsConfig) error {
	return azure.Unsupported(azure.Build, "set pipeline project settings")
}

type UnsupportedOverviewService struct{}

func (UnsupportedOverviewService) ReadOverview(context.Context, string) (config.OverviewConfig, error) {
	return config.OverviewConfig{}, azure.Unsupported(azure.Projects, "read project feature states")
}
func (UnsupportedOverviewService) SetOverview(context.Context, string, config.OverviewConfig) error {
	return azure.Unsupported(azure.Projects, "set project feature states")
}
