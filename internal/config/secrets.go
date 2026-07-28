package config

// Secrets is the separate sensitive YAML document.
type Secrets struct {
	ProjectSettings ProjectSettingsSecrets `yaml:"projectsettings"`
	Pipelines       PipelineSecrets        `yaml:"pipelines"`
}

type ProjectSettingsSecrets struct {
	ServiceHooks       []ServiceHookSecret       `yaml:"servicehook"`
	ServiceConnections []ServiceConnectionSecret `yaml:"serviceconnections"`
}

type PipelineSecrets struct {
	Library []VariableGroupSecret `yaml:"library"`
}

type ServiceHookSecret struct {
	Name  string `yaml:"name"`
	Event string `yaml:"event"`
	URL   string `yaml:"url"`
}

type ServiceConnectionSecret struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Auth        string `yaml:"auth"`
	URL         string `yaml:"url"`
	User        string `yaml:"user"`
	Password    string `yaml:"password"`
	APIKey      string `yaml:"apiKey"`
	Token       string `yaml:"token"`
	GrantAccess bool   `yaml:"grant_access"`
}

type VariableGroupSecret struct {
	Name      string           `yaml:"name"`
	Variables []SecretVariable `yaml:"variables"`
}

type SecretVariable struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}
