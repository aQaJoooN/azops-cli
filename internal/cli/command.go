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

// Parse validates an azops argument list and returns an apply command.
func Parse(args []string) (Command, error) {
	if len(args) == 0 || args[0] != "apply" {
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
