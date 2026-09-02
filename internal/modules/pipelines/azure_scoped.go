package pipelines

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
	"azops-cli/internal/domain"
	"azops-cli/internal/modules/permissions"
)

// buildNamespaceID is the fixed Azure DevOps Build security namespace ID.
const buildNamespaceID = "33344d9c-fc72-4d6f-aba5-fa317101a7e9"

// releaseNamespaceID is the fixed Azure DevOps Release Management security namespace ID.
const releaseNamespaceID = "c788c23e-1b46-4162-8f5e-d7585343b5de"

// buildPermissionBits maps config.yaml pipeline permission names to Build namespace bits.
// Confirmed from: GET /_apis/securitynamespaces/33344d9c-... actions
var buildPermissionBits = map[config.PermissionName]permissions.AccessBit{
	"View_builds":                           permissions.MakeAccessBit(buildNamespaceID, 1),
	"Edit_build_quality":                    permissions.MakeAccessBit(buildNamespaceID, 2),
	"Retain_indefinitely":                   permissions.MakeAccessBit(buildNamespaceID, 4),
	"Delete_builds":                         permissions.MakeAccessBit(buildNamespaceID, 8),
	"Manage_build_qualities":                permissions.MakeAccessBit(buildNamespaceID, 16),
	"Destroy_builds":                        permissions.MakeAccessBit(buildNamespaceID, 32),
	"Update_build_information":              permissions.MakeAccessBit(buildNamespaceID, 64),
	"Queue_builds":                          permissions.MakeAccessBit(buildNamespaceID, 128),
	"Manage_build_queue":                    permissions.MakeAccessBit(buildNamespaceID, 256),
	"Stop_builds":                           permissions.MakeAccessBit(buildNamespaceID, 512),
	"View_build_pipeline":                   permissions.MakeAccessBit(buildNamespaceID, 1024),
	"Edit_build_pipeline":                   permissions.MakeAccessBit(buildNamespaceID, 2048),
	"Delete_build_pipeline":                 permissions.MakeAccessBit(buildNamespaceID, 4096),
	"Override_check-in_validation_by_build": permissions.MakeAccessBit(buildNamespaceID, 8192),
	"Administer_build_permissions":          permissions.MakeAccessBit(buildNamespaceID, 16384),
}

// releasePermissionBits maps config.yaml release permission names to Release namespace bits.
// Confirmed from: GET /_apis/securitynamespaces/c788c23e-... actions
var releasePermissionBits = map[config.PermissionName]permissions.AccessBit{
	"View_release_pipeline":          permissions.MakeAccessBit(releaseNamespaceID, 1),
	"Edit_release_pipeline":          permissions.MakeAccessBit(releaseNamespaceID, 2),
	"Delete_release_pipeline":        permissions.MakeAccessBit(releaseNamespaceID, 4),
	"Manage_release_approvers":       permissions.MakeAccessBit(releaseNamespaceID, 8),
	"Manage_releases":                permissions.MakeAccessBit(releaseNamespaceID, 16),
	"View_releases":                  permissions.MakeAccessBit(releaseNamespaceID, 32),
	"Create_releases":                permissions.MakeAccessBit(releaseNamespaceID, 64),
	"Edit_release_stage":             permissions.MakeAccessBit(releaseNamespaceID, 128),
	"Delete_release_stage":           permissions.MakeAccessBit(releaseNamespaceID, 256),
	"Administer_release_permissions": permissions.MakeAccessBit(releaseNamespaceID, 512),
	"Delete_releases":                permissions.MakeAccessBit(releaseNamespaceID, 1024),
	"Manage_deployments":             permissions.MakeAccessBit(releaseNamespaceID, 2048),
}

// AzurePipelineScopedService implements ScopedPermissionService for build pipelines and releases.
type AzurePipelineScopedService struct {
	projects        *azure.Adapter
	securityACL     *azure.Adapter
	build           *azure.Adapter  // for build folder management
	release         *azure.Adapter  // for release folder management
	namespaceID     string
	bits            map[config.PermissionName]permissions.AccessBit
	isRelease       bool
}

func NewAzurePipelineScopedService(services azure.Services) *AzurePipelineScopedService {
	return &AzurePipelineScopedService{
		projects:    services.Projects,
		securityACL: services.SecurityACL,
		build:       services.Build,
		namespaceID: buildNamespaceID,
		bits:        buildPermissionBits,
		isRelease:   false,
	}
}

func NewAzureReleaseScopedService(services azure.Services) *AzurePipelineScopedService {
	return &AzurePipelineScopedService{
		projects:    services.Projects,
		securityACL: services.SecurityACL,
		release:     services.Release,
		namespaceID: releaseNamespaceID,
		bits:        releasePermissionBits,
		isRelease:   true,
	}
}

// resolveProjectID fetches the project GUID for a given project name.
func (s *AzurePipelineScopedService) resolveProjectID(ctx context.Context, project string) (string, error) {
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

// ensureBuildFolder creates the build pipeline folder if it doesn't exist.
func (s *AzurePipelineScopedService) ensureBuildFolder(ctx context.Context, project, folderPath string) error {
	// folderPath is like "/Dev" — convert to backslash for Azure DevOps API
	winPath := strings.ReplaceAll(folderPath, "/", "\\")
	body := map[string]string{"path": winPath}
	return s.build.Do(ctx, azure.Request{
		Project:    project,
		Method:     http.MethodPut,
		Path:       "folders",
		APIVersion: "7.1-preview.2",
		Query:      url.Values{"path": {winPath}},
		Body:       body,
	}, nil)
}

// ensureReleaseFolder creates the release pipeline folder if it doesn't exist.
// The path is passed as a query parameter (not URL segment) to avoid
// backslash encoding issues — Azure DevOps release folders use backslash paths.
func (s *AzurePipelineScopedService) ensureReleaseFolder(ctx context.Context, project, folderPath string) error {
	winPath := strings.ReplaceAll(folderPath, "/", "\\")
	body := map[string]string{"path": winPath}
	return s.release.Do(ctx, azure.Request{
		Project:    project,
		Method:     http.MethodPost,
		Path:       "folders",
		APIVersion: "7.1",
		Query:      url.Values{"path": {winPath}},
		Body:       body,
	}, nil)
}

// isDataspaceError returns true when Azure responds with a 500 DataspaceNotFoundException.
// This happens when the release management service has never been initialised for a
// project (i.e. no release pipeline has ever been created).
func isDataspaceError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *domain.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusInternalServerError &&
		strings.Contains(apiErr.Message, "DataspaceNotFoundException")
}

// bootstrapReleaseDataspace initialises the release management dataspace for a
// project that has never had a release pipeline. It does this by creating a
// release folder (the lightest API call that triggers dataspace initialisation)
// and falls back to creating a minimal throwaway pipeline definition if the
// folders API also requires the dataspace to already exist.
func (s *AzurePipelineScopedService) bootstrapReleaseDataspace(ctx context.Context, project string) error {
	// Try the lightest possible call first: create the root release folder.
	// On a fresh project this initialises the dataspace without needing a full
	// pipeline definition.
	folderErr := s.release.Do(ctx, azure.Request{
		Project:    project,
		Method:     http.MethodPost,
		Path:       "folders",
		APIVersion: "7.1",
		Query:      url.Values{"path": {"\\"}},
		Body:       map[string]string{"path": "\\"},
	}, nil)
	if folderErr == nil || !isDataspaceError(folderErr) {
		return nil
	}

	// Folder creation also hit the dataspace error — fall back to creating a
	// minimal release pipeline definition with all required fields.
	body := map[string]interface{}{
		"name":        "__azops_bootstrap__",
		"description": "temporary pipeline created by azops to initialise release management",
		"environments": []interface{}{
			map[string]interface{}{
				"name": "Stage 1",
				"rank": 1,
				"deployPhases": []interface{}{
					map[string]interface{}{
						"phaseType": 2, // agentless / server phase
						"name":      "Run on server",
						"rank":      1,
						"workflowTasks": []interface{}{
							map[string]interface{}{
								"taskId":  "9c3e8943-130d-4c78-ac63-8af81df62dfb", // Manual Intervention
								"version": "8.*",
								"name":    "bootstrap",
								"enabled": true,
								"inputs":  map[string]interface{}{},
							},
						},
					},
				},
				"preDeployApprovals": map[string]interface{}{
					"approvals": []interface{}{
						map[string]interface{}{"rank": 1, "isAutomated": true, "isNotificationOn": false},
					},
				},
				"postDeployApprovals": map[string]interface{}{
					"approvals": []interface{}{
						map[string]interface{}{"rank": 1, "isAutomated": true, "isNotificationOn": false},
					},
				},
				"retentionPolicy": map[string]interface{}{
					"daysToKeep": 30, "releasesToKeep": 3, "retainBuild": true,
				},
			},
		},
		"artifacts": []interface{}{},
	}
	var created struct {
		ID int `json:"id"`
	}
	if err := s.release.Do(ctx, azure.Request{
		Project:    project,
		Method:     http.MethodPost,
		Path:       "definitions",
		APIVersion: "7.1",
		Body:       body,
	}, &created); err != nil {
		return fmt.Errorf("bootstrap release dataspace (create): %w", err)
	}
	if created.ID == 0 {
		return fmt.Errorf("bootstrap release dataspace: created pipeline has no ID")
	}
	// Delete the throwaway pipeline — non-fatal if it fails.
	_ = s.release.Do(ctx, azure.Request{
		Project:    project,
		Method:     http.MethodDelete,
		Path:       fmt.Sprintf("definitions/%d", created.ID),
		APIVersion: "7.1",
	}, nil)
	return nil
}

// buildToken converts a canonical path to the ACL token format for builds.
// Root "/" → "{projectId}", "/Dev" → "{projectId}/Dev"
func buildToken(projectID, canonicalPath string) string {
	if canonicalPath == "/" {
		return projectID
	}
	folder := strings.TrimPrefix(canonicalPath, "/")
	return projectID + "/" + folder
}

// releaseToken converts a canonical path to the ACL token for releases.
// Root "/" → "{projectId}", "/Dev" → "{projectId}/Dev"
// The release security namespace uses forward-slash separation, same as builds.
func releaseToken(projectID, canonicalPath string) string {
	if canonicalPath == "/" {
		return projectID
	}
	folder := strings.TrimPrefix(canonicalPath, "/")
	return projectID + "/" + folder
}

// ReadScopedAccess reads the current ACL for a pipeline folder path.
func (s *AzurePipelineScopedService) ReadScopedAccess(ctx context.Context, project, path string) (AccessSnapshot, error) {
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return AccessSnapshot{}, err
	}

	var token string
	if s.isRelease {
		token = releaseToken(projectID, path)
	} else {
		token = buildToken(projectID, path)
	}

	var aclResp struct {
		Value []struct {
			InheritPermissions bool `json:"inheritPermissions"`
			AcesDictionary     map[string]struct {
				Allow int `json:"allow"`
				Deny  int `json:"deny"`
			} `json:"acesDictionary"`
		} `json:"value"`
	}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:       "accesscontrollists/" + s.namespaceID,
		APIVersion: "7.1",
		Query: url.Values{
			"token":               {token},
			"includeExtendedInfo": {"false"},
			"recurse":             {"false"},
		},
	}, &aclResp); err != nil {
		// Release management dataspace doesn't exist yet (no pipeline ever created).
		// Treat it as an empty ACL — SetScopedAccess will bootstrap before writing.
		if s.isRelease && isDataspaceError(err) {
			return AccessSnapshot{Bits: s.bits, Values: make(map[string]map[permissions.AccessBit]config.AccessValue)}, nil
		}
		return AccessSnapshot{}, fmt.Errorf("read ACL for %q: %w", path, err)
	}

	values := make(map[string]map[permissions.AccessBit]config.AccessValue)
	for _, acl := range aclResp.Value {
		// If a sub-folder has inheritance forcibly disabled, treat its ACEs as
		// empty so the planner triggers a re-apply that restores inheritPermissions:true.
		if path != "/" && !acl.InheritPermissions {
			return AccessSnapshot{Bits: s.bits, Values: values}, nil
		}
		for descriptor, ace := range acl.AcesDictionary {
			perDesc := make(map[permissions.AccessBit]config.AccessValue)
			for _, bit := range s.bits {
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
	return AccessSnapshot{Bits: s.bits, Values: values}, nil
}

// SetScopedAccess creates the folder if needed and writes ACEs.
// Inheritance is kept enabled on all paths. Only explicit Allow/Deny entries
// are written; Not_Set groups get no ACE entry and inherit from the parent.
func (s *AzurePipelineScopedService) SetScopedAccess(ctx context.Context, project, path string, changes []permissions.AccessChange, allACEs []permissions.AccessChange) error {
	projectID, err := s.resolveProjectID(ctx, project)
	if err != nil {
		return err
	}

	// Ensure the folder exists before writing permissions.
	if path != "/" {
		if s.isRelease {
			_ = s.ensureReleaseFolder(ctx, project, path)
		} else {
			_ = s.ensureBuildFolder(ctx, project, path)
		}
	}

	var token string
	if s.isRelease {
		token = releaseToken(projectID, path)
	} else {
		token = buildToken(projectID, path)
	}

	type ace struct{ allow, deny int }

	byDescriptor := make(map[string]*ace)
	for _, change := range changes {
		// Not_Set means no explicit ACE — skip it and let inheritance handle it.
		if change.Desired == config.AccessNotSet {
			continue
		}
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

	if path != "/" {
		// Sub-folders: use the accesscontrollists endpoint so we can set both
		// inheritPermissions and acesDictionary in a single call.
		// inheritPermissions is kept true so the folder inherits from its parent.
		type aceListEntry struct {
			Descriptor string `json:"descriptor"`
			Allow      int    `json:"allow"`
			Deny       int    `json:"deny"`
		}
		aceDict := make(map[string]aceListEntry, len(byDescriptor))
		for descriptor, a := range byDescriptor {
			aceDict[descriptor] = aceListEntry{Descriptor: descriptor, Allow: a.allow, Deny: a.deny}
		}
		type aclEntry struct {
			Token              string                  `json:"token"`
			InheritPermissions bool                    `json:"inheritPermissions"`
			AcesDictionary     map[string]aceListEntry `json:"acesDictionary"`
		}
		type aclListPayload struct {
			Value []aclEntry `json:"value"`
		}
		payload := aclListPayload{Value: []aclEntry{{
			Token:              token,
			InheritPermissions: true,
			AcesDictionary:     aceDict,
		}}}
		if err := s.securityACL.Do(ctx, azure.Request{
			Path:       "accesscontrollists/" + s.namespaceID,
			Method:     http.MethodPost,
			APIVersion: "7.1",
			Body:       payload,
		}, nil); err != nil {
			if s.isRelease && isDataspaceError(err) {
				if bootstrapErr := s.bootstrapReleaseDataspace(ctx, project); bootstrapErr != nil {
					return bootstrapErr
				}
				if folderErr := s.ensureReleaseFolder(ctx, project, path); folderErr != nil {
					return fmt.Errorf("create release folder %q (after bootstrap): %w", path, folderErr)
				}
				if retryErr := s.securityACL.Do(ctx, azure.Request{
					Path:       "accesscontrollists/" + s.namespaceID,
					Method:     http.MethodPost,
					APIVersion: "7.1",
					Body:       payload,
				}, nil); retryErr != nil {
					return fmt.Errorf("set permissions for %q (after bootstrap): %w", path, retryErr)
				}
				return nil
			}
			return fmt.Errorf("set permissions for %q: %w", path, err)
		}
		return nil
	}

	// Root path: use the AccessControlEntries endpoint with merge:true so system
	// entries are preserved.
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
	payload := aclPayload{Token: token, Merge: true, AccessControlEntries: entries}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:       "AccessControlEntries/" + s.namespaceID,
		Method:     http.MethodPost,
		APIVersion: "7.1",
		Body:       payload,
	}, nil); err != nil {
		if s.isRelease && isDataspaceError(err) {
			if bootstrapErr := s.bootstrapReleaseDataspace(ctx, project); bootstrapErr != nil {
				return bootstrapErr
			}
			if retryErr := s.securityACL.Do(ctx, azure.Request{
				Path:       "AccessControlEntries/" + s.namespaceID,
				Method:     http.MethodPost,
				APIVersion: "7.1",
				Body:       payload,
			}, nil); retryErr != nil {
				return fmt.Errorf("set permissions for %q (after bootstrap): %w", path, retryErr)
			}
			return nil
		}
		return fmt.Errorf("set permissions for %q: %w", path, err)
	}
	return nil
}
