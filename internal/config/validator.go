package config

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"azops-cli/internal/domain"
)

var supportedComponents = map[string]map[string]struct{}{
	"general":         stringSet(),
	"projectsettings": stringSet("overview", "security", "servicehook", "dashboards", "repositories", "agentpools", "settings", "release", "serviceconnections", "test"),
	"pipelines":       stringSet("pipelines", "environments", "library", "releases", "taskgroups", "deploymentgroup"),
}

// Validate performs semantic validation after a command selection is known.
func Validate(selection domain.Selection, loaded LoadedInputs) error {
	v := validator{selection: selection, loaded: loaded, aliases: make(map[GroupSelector]struct{})}
	v.validateSelection()
	v.validateGeneral()
	v.validateConfiguration()
	v.validateSecrets()
	if len(v.errors) == 0 {
		return nil
	}
	sort.SliceStable(v.errors, func(i, j int) bool {
		if v.errors[i].Field == v.errors[j].Field {
			return v.errors[i].Message < v.errors[j].Message
		}
		return v.errors[i].Field < v.errors[j].Field
	})
	return &domain.ValidationError{Errors: v.errors}
}

type validator struct {
	selection domain.Selection
	loaded    LoadedInputs
	aliases   map[GroupSelector]struct{}
	errors    []domain.FieldError
}

func (v *validator) addConfig(field, message string) {
	v.add(v.loaded.ConfigPath, "config", field, message)
}

func (v *validator) addSecret(field, message string) {
	v.add(v.loaded.SecretPath, "secret", field, message)
}

func (v *validator) add(path, fallback, field, message string) {
	if path == "" {
		path = fallback
	}
	v.errors = append(v.errors, domain.FieldError{Field: path + ":" + field, Message: message})
}

func (v *validator) validateSelection() {
	path := string(v.selection.Path)
	switch v.selection.Kind {
	case domain.SelectionAll:
		return
	case domain.SelectionRoot:
		if _, ok := supportedComponents[path]; !ok {
			v.addConfig("selection", fmt.Sprintf("unsupported root component %q", path))
		}
	case domain.SelectionComponent:
		parts := strings.Split(path, ".")
		if len(parts) != 2 {
			v.addConfig("selection", fmt.Sprintf("unsupported component path %q", path))
			return
		}
		children, ok := supportedComponents[parts[0]]
		if _, childOK := children[parts[1]]; !ok || !childOK {
			v.addConfig("selection", fmt.Sprintf("unsupported component path %q", path))
			return
		}
		if !componentPresent(v.loaded.Config, path) {
			v.addConfig(path, "selected component is absent from configuration")
		}
	default:
		v.addConfig("selection", fmt.Sprintf("unsupported selection kind %q", v.selection.Kind))
	}
}

func (v *validator) selected(path string) bool {
	switch v.selection.Kind {
	case domain.SelectionAll:
		return componentPresent(v.loaded.Config, path)
	case domain.SelectionRoot:
		return strings.HasPrefix(path, string(v.selection.Path)+".") && componentPresent(v.loaded.Config, path)
	case domain.SelectionComponent:
		return path == string(v.selection.Path) && componentPresent(v.loaded.Config, path)
	default:
		return false
	}
}

func componentPresent(cfg Config, path string) bool {
	switch path {
	case "projectsettings.overview":
		return cfg.ProjectSettings.Overview != nil
	case "projectsettings.security":
		return cfg.ProjectSettings.Security != nil
	case "projectsettings.servicehook":
		return cfg.ProjectSettings.ServiceHook != nil
	case "projectsettings.dashboards":
		return cfg.ProjectSettings.Dashboards != nil
	case "projectsettings.repositories":
		return cfg.ProjectSettings.Repositories != nil
	case "projectsettings.agentpools":
		return cfg.ProjectSettings.AgentPools != nil
	case "projectsettings.settings":
		return cfg.ProjectSettings.Settings != nil
	case "projectsettings.release":
		return cfg.ProjectSettings.Release != nil
	case "projectsettings.serviceconnections":
		return cfg.ProjectSettings.ServiceConnections != nil
	case "projectsettings.test":
		return cfg.ProjectSettings.Test != nil
	case "pipelines.pipelines":
		return cfg.Pipelines.Pipelines != nil
	case "pipelines.environments":
		return cfg.Pipelines.Environments != nil
	case "pipelines.library":
		return cfg.Pipelines.Library != nil
	case "pipelines.releases":
		return cfg.Pipelines.Releases != nil
	case "pipelines.taskgroups":
		return cfg.Pipelines.TaskGroups != nil
	case "pipelines.deploymentgroup":
		return cfg.Pipelines.DeploymentGroup != nil
	default:
		return false
	}
}

func (v *validator) validateGeneral() {
	general := v.loaded.Config.General
	if strings.TrimSpace(general.TeamProjectName) == "" {
		v.addConfig("general.teamprojectname", "value is required")
	}
	if len(general.GroupsAlias) == 0 {
		v.addConfig("general.groupsalias", "at least one group alias is required")
	}
	teams := sortedMapKeys(general.GroupsAlias)
	for _, team := range teams {
		if strings.TrimSpace(team) == "" {
			v.addConfig("general.groupsalias", "team name is required")
		}
		roles := general.GroupsAlias[team]
		if len(roles) == 0 {
			v.addConfig("general.groupsalias."+team, "at least one role alias is required")
		}
		for _, role := range sortedMapKeys(roles) {
			field := "general.groupsalias." + team + "." + role
			alias := GroupSelector(strings.TrimSpace(roles[role]))
			if strings.TrimSpace(role) == "" {
				v.addConfig(field, "role name is required")
			}
			if alias == "" || alias == "all" {
				v.addConfig(field, "alias must be non-empty and different from all")
				continue
			}
			if _, exists := v.aliases[alias]; exists {
				v.addConfig(field, fmt.Sprintf("duplicate group alias %q", alias))
			}
			v.aliases[alias] = struct{}{}
		}
	}
	template := general.GroupNameTemplate
	if strings.TrimSpace(template) == "" {
		v.addConfig("general.groupnametemplate", "value is required")
	} else {
		withoutProject := template
		if !strings.Contains(template, "teamprojectname") {
			v.addConfig("general.groupnametemplate", "missing placeholder \"teamprojectname\"")
		} else {
			withoutProject = strings.ReplaceAll(template, "teamprojectname", "")
		}
		if !strings.Contains(withoutProject, "team") {
			v.addConfig("general.groupnametemplate", "missing placeholder \"team\"")
		}
		if !strings.Contains(template, "role") {
			v.addConfig("general.groupnametemplate", "missing placeholder \"role\"")
		}
	}
}

func (v *validator) validateConfiguration() {
	cfg := v.loaded.Config
	if c := cfg.ProjectSettings.Overview; c != nil {
		v.validateEnableDisable("projectsettings.overview.boards", c.Boards)
		v.validateEnableDisable("projectsettings.overview.repos", c.Repos)
		v.validateEnableDisable("projectsettings.overview.pipelines", c.Pipelines)
		v.validateEnableDisable("projectsettings.overview.testplans", c.TestPlans)
		v.validateEnableDisable("projectsettings.overview.artifacts", c.Artifacts)
	}
	if c := cfg.ProjectSettings.Settings; c != nil {
		v.positive("projectsettings.settings.Retention_policy.Days_to_keep_artifacts_symbols_and_attachments", c.RetentionPolicy.ArtifactDays)
		v.positive("projectsettings.settings.Retention_policy.Days_to_keep_runs", c.RetentionPolicy.RunDays)
		v.positive("projectsettings.settings.Retention_policy.Days_to_keep_pull_request_runs", c.RetentionPolicy.PullRequestDays)
		v.positive("projectsettings.settings.Retention_policy.Number_of_recent_runs_to_retain_per_pipeline", c.RetentionPolicy.RecentRunCount)
		settings := map[string]OnOff{
			"Disable_anonymous_access_to_badges":                                         c.General.DisableAnonymousBadges,
			"Limit_variables_that_can_be_set_at_queue_time":                              c.General.LimitQueueTimeVariables,
			"Limit_job_authorization_scope_to_current_project_for_non-release_pipelines": c.General.LimitNonReleaseAuthorization,
			"Limit_job_authorization_scope_to_current_project_for_release_pipelines":     c.General.LimitReleaseAuthorization,
			"Publish_metadata_from_pipelines":                                            c.General.PublishMetadata,
			"Protect_access_to_repositories_in_YAML_pipelines":                           c.General.ProtectYAMLRepositories,
			"Disable_creation_of_classic_build_pipelines":                                c.General.DisableClassicBuild,
			"Disable_creation_of_classic_release_pipelines":                              c.General.DisableClassicRelease,
			"Enable_shell_tasks_arguments_validation":                                    c.General.EnableShellArgumentValidation,
		}
		for _, name := range sortedMapKeys(settings) {
			v.validateOnOff("projectsettings.settings.General."+name, settings[name])
		}
		v.validateOnOff("projectsettings.settings.Triggers.Disable_implied_YAML_CI_trigger", c.Triggers.DisableImpliedYAMLCI)
	}
	if c := cfg.ProjectSettings.Security; c != nil {
		v.validateAccess("projectsettings.security.permissions", c.Permissions)
	}
	if c := cfg.ProjectSettings.Repositories; c != nil {
		if !maximumFileSizePattern.MatchString(strings.TrimSpace(c.Policies.MaximumFileSize)) {
			v.addConfig("projectsettings.repositories.policies.Maximum_file_size", "expected a positive size such as 10 MB")
		}
		v.validateAccess("projectsettings.repositories.permissions", c.Permissions)
	}
	if c := cfg.ProjectSettings.Release; c != nil {
		v.positive("projectsettings.release.Maximum_retention_policy.Days_to_retain_a_release", c.MaximumRetention.DaysToRetain)
		v.positive("projectsettings.release.Maximum_retention_policy.Minimum_releases_to_keep", c.MaximumRetention.MinimumKeep)
		v.positive("projectsettings.release.Default_retention_policy.Days_to_retain_a_release", c.DefaultRetention.DaysToRetain)
		v.positive("projectsettings.release.Default_retention_policy.Minimum_releases_to_keep", c.DefaultRetention.MinimumKeep)
		v.positive("projectsettings.release.Permanently_destroy_releases.Days_to_keep_releases_after_deletion", c.DestroyReleases.DaysAfterDeletion)
	}
	if c := cfg.ProjectSettings.Test; c != nil {
		v.positive("projectsettings.test.Retention.Days_to_keep_automated_test_runs_results_and_attachments_when_not_associated_with_pipeline", c.Retention.AutomatedRunDays)
		v.positive("projectsettings.test.Retention.Days_to_keep_manual_test_runs_results_and_attachments", c.Retention.ManualRunDays)
	}
	if c := cfg.ProjectSettings.AgentPools; c != nil {
		seen := map[string]struct{}{}
		for i, pool := range c.Permissions {
			field := fmt.Sprintf("projectsettings.agentpools.permissions[%d]", i)
			v.validateUniqueName(field+".agentPoolName", pool.Name, seen)
			v.validateRoles(field+".permission", pool.Permission)
		}
	}
	if c := cfg.ProjectSettings.ServiceHook; c != nil {
		v.validateNames("projectsettings.servicehook.create", c.Create)
	}
	if c := cfg.ProjectSettings.ServiceConnections; c != nil {
		v.validateNames("projectsettings.serviceconnections.create", c.Create)
		v.validateRoles("projectsettings.serviceconnections.permissions", c.Permissions)
	}
	if c := cfg.Pipelines.Pipelines; c != nil {
		v.validateScopes("pipelines.pipelines.permissions", c.Permissions)
	}
	if c := cfg.Pipelines.Environments; c != nil {
		v.validateRoles("pipelines.environments.permissions", c.Permissions)
	}
	if c := cfg.Pipelines.Library; c != nil {
		v.validateNames("pipelines.library.create", c.Create)
		v.validateRoles("pipelines.library.permissions", c.Permissions)
	}
	if c := cfg.Pipelines.Releases; c != nil {
		v.validateScopes("pipelines.releases.permissions", c.Permissions)
	}
	if c := cfg.Pipelines.TaskGroups; c != nil {
		v.validateAccess("pipelines.taskgroups.permissions", c.Permissions)
	}
	if c := cfg.Pipelines.DeploymentGroup; c != nil {
		v.validateRoles("pipelines.deploymentgroup.permissions", c.Permissions)
	}
}

func (v *validator) validateNames(field string, names []string) {
	seen := map[string]struct{}{}
	for i, name := range names {
		v.validateUniqueName(fmt.Sprintf("%s[%d]", field, i), name, seen)
	}
}

var maximumFileSizePattern = regexp.MustCompile(`(?i)^[1-9][0-9]*\s*(B|KB|MB|GB)$`)

func (v *validator) positive(field string, value int) {
	if value <= 0 {
		v.addConfig(field, "value must be greater than zero")
	}
}

func (v *validator) validateHTTPURL(field, value string) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		v.addSecret(field, "expected an absolute HTTP or HTTPS URL")
	}
}

func validServiceHookEvent(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(value, "ms.vss-") ||
		value == "pull request commented on" ||
		value == "pull request created" ||
		value == "pull request updated"
}

func (v *validator) validateUniqueName(field, name string, seen map[string]struct{}) {
	name = strings.TrimSpace(name)
	if name == "" {
		v.addConfig(field, "name is required")
		return
	}
	if _, exists := seen[name]; exists {
		v.addConfig(field, fmt.Sprintf("duplicate resource name %q", name))
	}
	seen[name] = struct{}{}
}

func (v *validator) validateScopes(field string, scopes []ScopedPermissions) {
	seen := map[string]struct{}{}
	for i, scope := range scopes {
		item := fmt.Sprintf("%s[%d]", field, i)
		canonical := canonicalScopePath(scope.Path)
		if canonical == "" {
			v.addConfig(item+".path", "path is required")
		} else {
			if _, exists := seen[canonical]; exists {
				v.addConfig(item+".path", fmt.Sprintf("duplicate resource path %q", canonical))
			}
			seen[canonical] = struct{}{}
		}
		v.validateAccess(item+".permission", scope.Permission)
	}
}

func canonicalScopePath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" {
		return ""
	}
	if strings.EqualFold(value, "root") || value == "/" {
		return "/"
	}
	return path.Clean("/" + strings.Trim(value, "/"))
}

func (v *validator) validateEnableDisable(field string, value EnableDisable) {
	if value != Enable && value != Disable {
		v.addConfig(field, fmt.Sprintf("unsupported value %q", value))
	}
}

func (v *validator) validateOnOff(field string, value OnOff) {
	if value != On && value != Off {
		v.addConfig(field, fmt.Sprintf("unsupported value %q", value))
	}
}

func (v *validator) validateAccess(field string, assignments AccessAssignments) {
	for _, permission := range sortedPermissionKeys(assignments) {
		permissionField := field + "." + string(permission)
		if strings.TrimSpace(string(permission)) == "" {
			v.addConfig(field, "permission name is required")
		}

		seen := map[GroupSelector]AccessValue{}
		values := assignments[permission]
		for access := range values {
			if access != AccessAllow && access != AccessDeny && access != AccessNotSet {
				v.addConfig(permissionField, fmt.Sprintf("unsupported access value %q", access))
			}
		}
		for _, access := range []AccessValue{AccessAllow, AccessDeny, AccessNotSet} {
			for i, group := range values[access] {
				path := fmt.Sprintf("%s.%s[%d]", permissionField, access, i)
				v.validateSelector(path, group)
				if previous, exists := seen[group]; exists {
					if previous != access {
						v.addConfig(path, fmt.Sprintf("group %q is also assigned access %q", group, previous))
					} else {
						v.addConfig(path, fmt.Sprintf("duplicate group selector %q", group))
					}
				}
				seen[group] = access
			}
		}
		if allAccess, exists := seen["all"]; exists {
			for group, access := range seen {
				if group != "all" && access != allAccess {
					v.addConfig(permissionField, fmt.Sprintf("group %q conflicts with all selector access %q", group, allAccess))
				}
			}
		}
	}
}

func (v *validator) validateRoles(field string, assignments RoleAssignments) {
	seen := map[GroupSelector]Role{}
	roles := make([]Role, 0, len(assignments))
	for role := range assignments {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	for _, role := range roles {
		if role != RoleAdministrator && role != RoleAdmin && role != RoleCreator && role != RoleUser && role != RoleReader {
			v.addConfig(field, fmt.Sprintf("unsupported role %q", role))
		}
		for i, group := range assignments[role] {
			path := fmt.Sprintf("%s.%s[%d]", field, role, i)
			v.validateSelector(path, group)
			if previous, exists := seen[group]; exists {
				if previous != role {
					v.addConfig(path, fmt.Sprintf("group %q is also assigned role %q", group, previous))
				} else {
					v.addConfig(path, fmt.Sprintf("duplicate group selector %q", group))
				}
			}
			seen[group] = role
		}
	}
	if allRole, exists := seen["all"]; exists {
		for group, role := range seen {
			if group != "all" && role != allRole {
				v.addConfig(field, fmt.Sprintf("group %q conflicts with all selector role %q", group, allRole))
			}
		}
	}
}

func (v *validator) validateSelector(field string, selector GroupSelector) {
	if selector == "all" {
		return
	}
	if strings.TrimSpace(string(selector)) == "" {
		v.addConfig(field, "group selector is required")
		return
	}
	if _, exists := v.aliases[selector]; !exists {
		v.addConfig(field, fmt.Sprintf("group alias %q is not configured", selector))
	}
}

func (v *validator) validateSecrets() {
	if v.selected("projectsettings.servicehook") && v.loaded.Config.ProjectSettings.ServiceHook != nil {
		v.matchServiceHooks(v.loaded.Config.ProjectSettings.ServiceHook.Create)
	}
	if v.selected("projectsettings.serviceconnections") && v.loaded.Config.ProjectSettings.ServiceConnections != nil {
		v.matchServiceConnections(v.loaded.Config.ProjectSettings.ServiceConnections.Create)
	}
	if v.selected("pipelines.library") && v.loaded.Config.Pipelines.Library != nil {
		v.matchVariableGroups(v.loaded.Config.Pipelines.Library.Create)
	}
}

func (v *validator) matchServiceHooks(create []string) {
	byName := map[string][]int{}
	for i, secret := range v.loaded.Secrets.ProjectSettings.ServiceHooks {
		byName[secret.Name] = append(byName[secret.Name], i)
	}
	for i, name := range create {
		indexes := byName[name]
		field := fmt.Sprintf("projectsettings.servicehook.create[%d]", i)
		if !v.requireOne(field, name, indexes, "projectsettings.servicehook") {
			continue
		}
		secret := v.loaded.Secrets.ProjectSettings.ServiceHooks[indexes[0]]
		base := fmt.Sprintf("projectsettings.servicehook[%d]", indexes[0])
		v.requireSecret(base+".event", secret.Event)
		if strings.TrimSpace(secret.Event) != "" && !validServiceHookEvent(secret.Event) {
			v.addSecret(base+".event", "unsupported service hook event")
		}
		v.requireSecret(base+".url", secret.URL)
		if strings.TrimSpace(secret.URL) != "" {
			v.validateHTTPURL(base+".url", secret.URL)
		}
	}
}

func (v *validator) matchServiceConnections(create []string) {
	byName := map[string][]int{}
	for i, secret := range v.loaded.Secrets.ProjectSettings.ServiceConnections {
		byName[secret.Name] = append(byName[secret.Name], i)
	}
	for i, name := range create {
		indexes := byName[name]
		field := fmt.Sprintf("projectsettings.serviceconnections.create[%d]", i)
		if !v.requireOne(field, name, indexes, "projectsettings.serviceconnections") {
			continue
		}
		index := indexes[0]
		secret := v.loaded.Secrets.ProjectSettings.ServiceConnections[index]
		base := fmt.Sprintf("projectsettings.serviceconnections[%d]", index)
		v.requireSecret(base+".type", secret.Type)
		v.requireSecret(base+".url", secret.URL)
		if strings.TrimSpace(secret.URL) != "" {
			v.validateHTTPURL(base+".url", secret.URL)
		}
		v.validateServiceConnection(base, secret)
	}
}

func (v *validator) validateServiceConnection(field string, secret ServiceConnectionSecret) {
	typeName := strings.ToLower(strings.TrimSpace(secret.Type))
	auth := strings.ToLower(strings.TrimSpace(secret.Auth))
	switch typeName {
	case "docker registry", "dockerregistry":
		v.requireSecret(field+".user", secret.User)
		v.requireSecret(field+".password", secret.Password)
	case "nuget":
		if auth != "apikey" && auth != "api key" {
			v.addSecret(field+".auth", "NuGet service connection requires ApiKey authentication")
		}
		v.requireSecret(field+".apiKey", secret.APIKey)
	case "npm":
		switch auth {
		case "user and pass", "usernamepassword", "username and password":
			v.requireSecret(field+".password", secret.Password)
		case "token":
			v.requireSecret(field+".token", secret.Token)
		default:
			v.addSecret(field+".auth", fmt.Sprintf("unsupported authentication %q for npm service connection", secret.Auth))
		}
	case "sonarqube", "sonarqubeconnection":
		switch auth {
		case "user and pass", "usernamepassword", "username and password":
			v.requireSecret(field+".password", secret.Password)
		case "token":
			v.requireSecret(field+".token", secret.Token)
		default:
			v.addSecret(field+".auth", fmt.Sprintf("unsupported authentication %q for SonarQube service connection", secret.Auth))
		}
	case "generic":
		switch auth {
		case "user and pass", "usernamepassword", "username and password":
			v.requireSecret(field+".password", secret.Password)
		case "token":
			v.requireSecret(field+".token", secret.Token)
		case "apikey", "api key":
			v.requireSecret(field+".apiKey", secret.APIKey)
		default:
			v.addSecret(field+".auth", fmt.Sprintf("unsupported authentication %q for Generic service connection", secret.Auth))
		}
	default:
		v.addSecret(field+".type", fmt.Sprintf("unsupported service connection type %q", secret.Type))
	}
}

func (v *validator) matchVariableGroups(create []string) {
	byName := map[string][]int{}
	for i, secret := range v.loaded.Secrets.Pipelines.Library {
		byName[secret.Name] = append(byName[secret.Name], i)
	}
	for i, name := range create {
		indexes := byName[name]
		field := fmt.Sprintf("pipelines.library.create[%d]", i)
		if !v.requireOne(field, name, indexes, "pipelines.library") {
			continue
		}
		index := indexes[0]
		variables := v.loaded.Secrets.Pipelines.Library[index].Variables
		if len(variables) == 0 {
			v.addSecret(fmt.Sprintf("pipelines.library[%d].variables", index), "at least one variable is required")
		}
		seen := map[string]struct{}{}
		for j, variable := range variables {
			base := fmt.Sprintf("pipelines.library[%d].variables[%d]", index, j)
			variableName := strings.TrimSpace(variable.Name)
			if variableName == "" {
				v.addSecret(base+".name", "name is required")
			} else if _, exists := seen[variableName]; exists {
				v.addSecret(base+".name", fmt.Sprintf("duplicate variable name %q", variableName))
			}
			seen[variableName] = struct{}{}
			v.requireSecret(base+".value", variable.Value)
		}
	}
}

func (v *validator) requireOne(configField, name string, indexes []int, secretPath string) bool {
	if len(indexes) == 1 {
		return true
	}
	if len(indexes) == 0 {
		v.addSecret(secretPath, fmt.Sprintf("missing same-name secret entry %q required by %s", name, configField))
	} else {
		v.addSecret(secretPath, fmt.Sprintf("secret name %q matches %d entries; exactly one is required", name, len(indexes)))
	}
	return false
}

func (v *validator) requireSecret(field, value string) {
	if strings.TrimSpace(value) == "" {
		v.addSecret(field, "value is required")
	}
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedPermissionKeys(values AccessAssignments) []PermissionName {
	keys := make([]PermissionName, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
