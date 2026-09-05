package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"azops-cli/internal/domain"
)

// Command contains parsed apply input without executing the application.
type Command struct {
	Selection  domain.Selection
	ConfigPath string
	SecretPath string
	URL        string
	DryRun     bool
}

var supportedComponents = map[string]map[string]struct{}{
	"general":         names(),
	"projectsettings": names("overview", "security", "servicehook", "dashboards", "repositories", "agentpools", "settings", "release", "serviceconnections", "test"),
	"pipelines":       names("pipelines", "environments", "library", "releases", "taskgroups", "deploymentgroup"),
}

const helpText = `azops - Azure DevOps configuration management tool

Usage:
  azops apply <selector> [options]

Selectors:
  all                       apply all components
  <root>                    apply all components under a root (e.g. projectsettings)
  <root>.<component>        apply a single component (e.g. projectsettings.security)

Supported roots and components:
  projectsettings           overview, security, servicehook, dashboards, repositories,
                            agentpools, settings, release, serviceconnections, test
  pipelines                 pipelines, environments, library, releases, taskgroups, deploymentgroup

Options:
  -c, --config <file>       configuration file (or set AZOPS_CONFIG_FILE) (default: config.yaml)
  -s, --secret <file>       secret file (or set AZOPS_SECRET_FILE) (default: secret.yaml)
                            secret file is not required until using these components:
                             - projectsettings.servicehook.create
                             - projectsettings.serviceconnections.create
                             - pipelines.library.create
  -u, --url <url>           Azure DevOps Server URL (or set AZOPS_AZURE_URL)
      --dry-run             preview changes without applying them
  -h, --help                show this help message

Environment variables:
  AZOPS_AZURE_URL           Azure DevOps Server base URL
  AZOPS_AZURE_PAT           Azure DevOps personal access token
  AZOPS_CONFIG_FILE         configuration file path
  AZOPS_SECRET_FILE         secret file path

Examples:
  azops apply all
  azops apply projectsettings
  azops apply projectsettings.security --dry-run
  azops apply all -c config.yaml -s secret.yaml -u https://dev.azure.com/org
`

// Parse validates an azops argument list and returns an apply command.
func Parse(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, usage("expected command: apply <all|root|root.inner>", nil)
	}
	if args[0] == "-h" || args[0] == "--help" {
		return Command{}, &domain.HelpRequest{Text: helpText}
	}
	if args[0] != "apply" {
		return Command{}, usage("expected command: apply <all|root|root.inner>", nil)
	}

	var command Command
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&command.ConfigPath, "config", "", "configuration file")
	flags.StringVar(&command.ConfigPath, "c", "", "configuration file")
	flags.StringVar(&command.SecretPath, "secret", "", "secret file")
	flags.StringVar(&command.SecretPath, "s", "", "secret file")
	flags.StringVar(&command.URL, "url", "", "Azure DevOps Server URL")
	flags.StringVar(&command.URL, "u", "", "Azure DevOps Server URL")
	flags.BoolVar(&command.DryRun, "dry-run", false, "preview changes")

	optionArgs, selector, err := splitApplyArgs(args[1:])
	if err != nil {
		return Command{}, err
	}
	if err := flags.Parse(optionArgs); err != nil {
		return Command{}, usage("invalid apply options", err)
	}
	selection, err := parseSelection(selector)
	if err != nil {
		return Command{}, err
	}
	command.Selection = selection
	return command, nil
}

func splitApplyArgs(args []string) ([]string, string, error) {
	optionArgs := make([]string, 0, len(args))
	positionals := make([]string, 0, 1)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if strings.HasPrefix(argument, "-") {
			optionArgs = append(optionArgs, argument)
			name := strings.TrimLeft(strings.SplitN(argument, "=", 2)[0], "-")
			if name != "dry-run" && !strings.Contains(argument, "=") {
				if index+1 >= len(args) {
					return nil, "", usage("option requires a value: "+argument, nil)
				}
				index++
				optionArgs = append(optionArgs, args[index])
			}
			continue
		}
		positionals = append(positionals, argument)
	}
	if len(positionals) != 1 {
		return nil, "", usage("apply requires exactly one component selector", nil)
	}
	return optionArgs, positionals[0], nil
}

func parseSelection(value string) (domain.Selection, error) {
	if value == "all" {
		return domain.Selection{Kind: domain.SelectionAll}, nil
	}
	parts := strings.Split(value, ".")
	children, rootExists := supportedComponents[parts[0]]
	if len(parts) == 1 && rootExists {
		return domain.Selection{Kind: domain.SelectionRoot, Path: domain.ComponentPath(value)}, nil
	}
	if len(parts) == 2 && rootExists {
		if _, childExists := children[parts[1]]; childExists {
			return domain.Selection{Kind: domain.SelectionComponent, Path: domain.ComponentPath(value)}, nil
		}
	}
	return domain.Selection{}, usage(fmt.Sprintf("unsupported component selector %q", value), nil)
}

func names(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func usage(message string, err error) error {
	return &domain.UsageError{Message: message, Err: err}
}
