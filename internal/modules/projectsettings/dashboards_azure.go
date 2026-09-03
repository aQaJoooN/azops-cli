package projectsettings

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
)

// dashboardsNamespaceID is the fixed Azure DevOps DashboardsPrivileges security namespace ID.
const dashboardsNamespaceID = "8adf73b7-389a-4276-b638-fe1653f7efc7"

// Dashboard permission bits in the DashboardsPrivileges namespace.
const (
	dashboardBitRead              = 1
	dashboardBitCreate            = 2
	dashboardBitEdit              = 4
	dashboardBitDelete            = 8
	dashboardBitManagePermissions = 16
)

// AzureDashboardService implements DashboardService using the DashboardsPrivileges security namespace.
//
// The UI (Project Settings > Dashboards > Security) reads/writes the token "$/projectId/teamId"
// for the default team group descriptor (suffix -1-...).
// ManagePermissions (bit 16) is kept denied. Create/Edit/Delete: false => deny, true => allow.
type AzureDashboardService struct {
	projects    *azure.Adapter
	securityACL *azure.Adapter
}

func NewAzureDashboardService(services azure.Services) *AzureDashboardService {
	return &AzureDashboardService{
		projects:    services.Projects,
		securityACL: services.SecurityACL,
	}
}

// resolveProjectAndDefaultTeam returns the project GUID and default team GUID.
func (s *AzureDashboardService) resolveProjectAndDefaultTeam(ctx context.Context, project string) (projectID, teamID string, err error) {
	var projResponse struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := s.projects.Do(ctx, azure.Request{
		Path:       "",
		APIVersion: "7.0",
	}, &projResponse); err != nil {
		return "", "", fmt.Errorf("list projects: %w", err)
	}
	for _, p := range projResponse.Value {
		if strings.EqualFold(p.Name, project) {
			projectID = p.ID
			break
		}
	}
	if projectID == "" {
		return "", "", fmt.Errorf("project %q not found", project)
	}

	var teamsResponse struct {
		Value []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"value"`
	}
	if err := s.projects.Do(ctx, azure.Request{
		Path:       projectID + "/teams",
		APIVersion: "7.0",
	}, &teamsResponse); err != nil {
		return "", "", fmt.Errorf("list teams for project %q: %w", project, err)
	}
	if len(teamsResponse.Value) == 0 {
		return "", "", fmt.Errorf("no teams found for project %q", project)
	}
	teamID = teamsResponse.Value[0].ID
	for _, t := range teamsResponse.Value {
		if strings.EqualFold(t.Name, project+" Team") ||
			strings.Contains(strings.ToLower(t.Description), "default") {
			teamID = t.ID
			break
		}
	}
	return projectID, teamID, nil
}

// readTeamACE fetches the ACE for the default team at token $/projectId/teamId.
// Returns the team group descriptor and current allow/deny bits.
func (s *AzureDashboardService) readTeamACE(ctx context.Context, projectID, teamID string) (descriptor string, allow, deny int, err error) {
	token := "$/" + projectID + "/" + teamID

	var aclResponse struct {
		Value []struct {
			AcesDictionary map[string]struct {
				Allow int `json:"allow"`
				Deny  int `json:"deny"`
			} `json:"acesDictionary"`
		} `json:"value"`
	}
	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "accesscontrollists/" + dashboardsNamespaceID,
		SkipAPIVersion: true,
		Query:          url.Values{"token": {token}},
	}, &aclResponse); err != nil {
		return "", 0, 0, fmt.Errorf("read dashboard ACL: %w", err)
	}

	if len(aclResponse.Value) == 0 || len(aclResponse.Value[0].AcesDictionary) == 0 {
		return "", 0, 0, nil
	}

	// The team group descriptor ends in -1-... (not -0-0-0-0-1/2/3 which are system groups).
	for desc, ace := range aclResponse.Value[0].AcesDictionary {
		if !strings.HasSuffix(desc, "-0-0-0-0-1") &&
			!strings.HasSuffix(desc, "-0-0-0-0-2") &&
			!strings.HasSuffix(desc, "-0-0-0-0-3") {
			return desc, ace.Allow, ace.Deny, nil
		}
	}
	return "", 0, 0, nil
}

// ReadDashboardSecurity reads the current dashboard security state from the team ACL token.
func (s *AzureDashboardService) ReadDashboardSecurity(ctx context.Context, project string) (config.DashboardSecurity, error) {
	if s == nil || s.securityACL == nil {
		return config.DashboardSecurity{}, fmt.Errorf("security ACL adapter is required")
	}

	projectID, teamID, err := s.resolveProjectAndDefaultTeam(ctx, project)
	if err != nil {
		return config.DashboardSecurity{}, err
	}

	_, allowBits, denyBits, err := s.readTeamACE(ctx, projectID, teamID)
	if err != nil {
		return config.DashboardSecurity{}, err
	}

	// If no ACE found, defaults apply (all allowed).
	if allowBits == 0 && denyBits == 0 {
		return config.DashboardSecurity{Create: true, Edit: true, Delete: true}, nil
	}

	return config.DashboardSecurity{
		Create: denyBits&dashboardBitCreate == 0 && allowBits&dashboardBitCreate != 0,
		Edit:   denyBits&dashboardBitEdit == 0 && allowBits&dashboardBitEdit != 0,
		Delete: denyBits&dashboardBitDelete == 0 && allowBits&dashboardBitDelete != 0,
	}, nil
}

// SetDashboardSecurity applies dashboard security at the team ACL token.
// On a fresh project the ACL token doesn't exist yet (Azure creates it lazily after the first
// dashboard interaction). In that case ErrDashboardACLNotReady is returned — callers should
// treat this as a no-op and retry on the next run.
func (s *AzureDashboardService) SetDashboardSecurity(ctx context.Context, project string, cfg config.DashboardSecurity) error {
	if s == nil || s.securityACL == nil {
		return fmt.Errorf("security ACL adapter is required")
	}

	projectID, teamID, err := s.resolveProjectAndDefaultTeam(ctx, project)
	if err != nil {
		return err
	}

	descriptor, _, _, err := s.readTeamACE(ctx, projectID, teamID)
	if err != nil {
		return err
	}
	// ACL token not yet bootstrapped — signal the caller to skip silently.
	if descriptor == "" {
		return ErrDashboardACLNotReady
	}

	allowBits := dashboardBitRead
	denyBits := dashboardBitManagePermissions

	if cfg.Create {
		allowBits |= dashboardBitCreate
	} else {
		denyBits |= dashboardBitCreate
	}
	if cfg.Edit {
		allowBits |= dashboardBitEdit
	} else {
		denyBits |= dashboardBitEdit
	}
	if cfg.Delete {
		allowBits |= dashboardBitDelete
	} else {
		denyBits |= dashboardBitDelete
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

	payload := aclPayload{
		Token: "$/" + projectID + "/" + teamID,
		Merge: true,
		AccessControlEntries: []aceEntry{
			{Descriptor: descriptor, Allow: allowBits, Deny: denyBits},
		},
	}

	if err := s.securityACL.Do(ctx, azure.Request{
		Path:           "AccessControlEntries/" + dashboardsNamespaceID,
		Method:         http.MethodPost,
		SkipAPIVersion: true,
		Body:           payload,
	}, nil); err != nil {
		return fmt.Errorf("set dashboard permissions: %w", err)
	}
	return nil
}
