package config

// Config is the complete desired-state YAML document.
type Config struct {
	General         GeneralConfig          `yaml:"general"`
	ProjectSettings ProjectSettingsConfig `yaml:"projectsettings"`
	Pipelines       PipelinesConfig        `yaml:"pipelines"`
}

type GeneralConfig struct {
	TeamProjectName   string                       `yaml:"teamprojectname"`
	GroupsAlias       map[string]map[string]string `yaml:"groupsalias"`
	GroupNameTemplate string                       `yaml:"groupnametemplate"`
}

type ProjectSettingsConfig struct {
	Overview           *OverviewConfig           `yaml:"overview"`
	Security           *SecurityConfig           `yaml:"security"`
	ServiceHook        *CreateConfig             `yaml:"servicehook"`
	Dashboards         *DashboardsConfig         `yaml:"dashboards"`
	Repositories       *RepositoriesConfig       `yaml:"repositories"`
	AgentPools         *AgentPoolsConfig         `yaml:"agentpools"`
	Settings           *PipelineSettingsConfig   `yaml:"settings"`
	Release            *ReleaseRetentionConfig   `yaml:"release"`
	ServiceConnections *ServiceConnectionsConfig `yaml:"serviceconnections"`
	Test               *TestRetentionConfig      `yaml:"test"`
}

type PipelinesConfig struct {
	Pipelines       *ScopedPermissionsConfig `yaml:"pipelines"`
	Environments    *RolePermissionsConfig   `yaml:"environments"`
	Library         *LibraryConfig           `yaml:"library"`
	Releases        *ScopedPermissionsConfig `yaml:"releases"`
	TaskGroups      *AccessPermissionsConfig `yaml:"taskgroups"`
	DeploymentGroup *RolePermissionsConfig   `yaml:"deploymentgroup"`
}

type OverviewConfig struct {
	Boards    EnableDisable `yaml:"boards"`
	Repos     EnableDisable `yaml:"repos"`
	Pipelines EnableDisable `yaml:"pipelines"`
	TestPlans EnableDisable `yaml:"testplans"`
	Artifacts EnableDisable `yaml:"artifacts"`
}

type SecurityConfig struct {
	CreateGroup bool              `yaml:"creategroup"`
	Permissions AccessAssignments `yaml:"permissions"`
}

type CreateConfig struct {
	Create []string `yaml:"create"`
}

type DashboardsConfig struct {
	Security DashboardSecurity `yaml:"Security"`
}

type DashboardSecurity struct {
	Create bool `yaml:"Create_dashboards"`
	Edit   bool `yaml:"Edit_dashboards"`
	Delete bool `yaml:"Delete_dashboards"`
}

type RepositoriesConfig struct {
	Policies    RepositoryPolicies `yaml:"policies"`
	Permissions AccessAssignments  `yaml:"permissions"`
}

type RepositoryPolicies struct {
	MaximumFileSize string `yaml:"Maximum_file_size"`
}

type AgentPoolsConfig struct {
	Permissions []AgentPoolPermissions `yaml:"permissions"`
}

type AgentPoolPermissions struct {
	Name       string          `yaml:"agentPoolName"`
	Permission RoleAssignments `yaml:"permission"`
}

type PipelineSettingsConfig struct {
	RetentionPolicy RetentionPolicySettings  `yaml:"Retention_policy"`
	General         *GeneralPipelineSettings `yaml:"General"`
	Triggers        *TriggerSettings         `yaml:"Triggers"`
}

type RetentionPolicySettings struct {
	ArtifactDays      int `yaml:"Days_to_keep_artifacts_symbols_and_attachments"`
	RunDays           int `yaml:"Days_to_keep_runs"`
	PullRequestDays   int `yaml:"Days_to_keep_pull_request_runs"`
	RecentRunCount    int `yaml:"Number_of_recent_runs_to_retain_per_pipeline"`
}

type GeneralPipelineSettings struct {
	DisableAnonymousBadges          OnOff `yaml:"Disable_anonymous_access_to_badges"`
	LimitQueueTimeVariables         OnOff `yaml:"Limit_variables_that_can_be_set_at_queue_time"`
	LimitNonReleaseAuthorization    OnOff `yaml:"Limit_job_authorization_scope_to_current_project_for_non-release_pipelines"`
	LimitReleaseAuthorization       OnOff `yaml:"Limit_job_authorization_scope_to_current_project_for_release_pipelines"`
	PublishMetadata                 OnOff `yaml:"Publish_metadata_from_pipelines"`
	ProtectYAMLRepositories         OnOff `yaml:"Protect_access_to_repositories_in_YAML_pipelines"`
	DisableClassicBuild             OnOff `yaml:"Disable_creation_of_classic_build_pipelines"`
	DisableClassicRelease           OnOff `yaml:"Disable_creation_of_classic_release_pipelines"`
	EnableShellArgumentValidation   OnOff `yaml:"Enable_shell_tasks_arguments_validation"`
}

type TriggerSettings struct {
	DisableImpliedYAMLCI OnOff `yaml:"Disable_implied_YAML_CI_trigger"`
}

type ReleaseRetentionConfig struct {
	MaximumRetention  ReleasePolicy    `yaml:"Maximum_retention_policy"`
	DefaultRetention  ReleasePolicy    `yaml:"Default_retention_policy"`
	DestroyReleases   DestroyPolicy    `yaml:"Permanently_destroy_releases"`
}

type ReleasePolicy struct {
	DaysToRetain int  `yaml:"Days_to_retain_a_release"`
	MinimumKeep  int  `yaml:"Minimum_releases_to_keep"`
	RetainBuild  bool `yaml:"Retain_build"`
}

type DestroyPolicy struct {
	DaysAfterDeletion int `yaml:"Days_to_keep_releases_after_deletion"`
}

type ServiceConnectionsConfig struct {
	Create      []string        `yaml:"create"`
	Permissions RoleAssignments `yaml:"permissions"`
}

type TestRetentionConfig struct {
	Retention TestRetention `yaml:"Retention"`
}

type TestRetention struct {
	AutomatedRunDays int `yaml:"Days_to_keep_automated_test_runs_results_and_attachments_when_not_associated_with_pipeline"`
	ManualRunDays    int `yaml:"Days_to_keep_manual_test_runs_results_and_attachments"`
}

type AccessPermissionsConfig struct {
	Permissions AccessAssignments `yaml:"permissions"`
}

type RolePermissionsConfig struct {
	Permissions RoleAssignments `yaml:"permissions"`
}

type LibraryConfig struct {
	Create      []string        `yaml:"create"`
	Permissions RoleAssignments `yaml:"permissions"`
}

type ScopedPermissionsConfig struct {
	Permissions []ScopedPermissions `yaml:"permissions"`
}

type ScopedPermissions struct {
	Path       string            `yaml:"path"`
	Permission AccessAssignments `yaml:"permission"`
}

type GroupSelector string
type PermissionName string

type AccessAssignments map[PermissionName]map[AccessValue][]GroupSelector
type RoleAssignments map[Role][]GroupSelector
