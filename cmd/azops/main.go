package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"azops-cli/internal/azure"
	"azops-cli/internal/cli"
	"azops-cli/internal/config"
	"azops-cli/internal/detector"
	"azops-cli/internal/domain"
	"azops-cli/internal/report"
	"azops-cli/internal/runner"
)

const (
	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv, ".")
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, lookup cli.EnvironmentLookup, workingDir string) int {
	command, err := cli.Parse(args)
	if err != nil {
		var help *domain.HelpRequest
		if errors.As(err, &help) {
			_, _ = fmt.Fprint(stdout, help.Text)
			return exitSuccess
		}
		return writeFailure(stderr, report.Redactor{}, err)
	}
	connection, err := cli.ResolveConnection(command.URL, lookup)
	if err != nil {
		return writeFailure(stderr, report.Redactor{}, err)
	}

	loader := config.Loader{LookupEnv: func(key string) string {
		value, _ := lookup(key)
		return value
	}}
	loaded, err := loader.Load(ctx, config.LoadOptions{
		ConfigPath: command.ConfigPath, SecretPath: command.SecretPath, WorkingDir: workingDir,
	})
	if err != nil {
		return writeFailure(stderr, report.NewRedactor(connection.PAT, nil), err)
	}

	redactor := report.NewRedactor(connection.PAT, loaded.Secrets)
	reporter := report.New(stdout, redactor)
	if err := writeWarnings(reporter, loaded.Warnings); err != nil {
		return writeFailure(stderr, redactor, err)
	}
	if err := config.Validate(command.Selection, loaded); err != nil {
		return writeFailure(stderr, redactor, err)
	}
	client, err := azure.NewClient(connection.URL.String(), connection.PAT)
	if err != nil {
		return writeFailure(stderr, redactor, err)
	}
	registry := detector.NewRegistry(applicationDependencies(azure.NewServices(client)))
	graph, warnings, err := detector.New(registry).Detect(command.Selection, loaded.Config)
	if err != nil {
		return writeFailure(stderr, redactor, err)
	}
	if err := writeWarnings(reporter, warnings); err != nil {
		return writeFailure(stderr, redactor, err)
	}

	final := runner.New().Run(ctx, graph, domain.ModuleInput{
		DesiredState: loaded.Config,
		SecretState:  loaded.Secrets,
	}, runner.RunOptions{DryRun: command.DryRun})
	if err := reporter.Render(final); err != nil {
		return writeFailure(stderr, redactor, err)
	}
	if !final.Success {
		return exitFailure
	}
	return exitSuccess
}

func writeWarnings(reporter *report.Reporter, warnings []string) error {
	for _, warning := range warnings {
		if err := reporter.Warning(warning); err != nil {
			return err
		}
	}
	return nil
}

func writeFailure(writer io.Writer, redactor report.Redactor, err error) int {
	_, _ = fmt.Fprintf(writer, "Error: %s\n", redactor.Redact(err.Error()))
	var usage *domain.UsageError
	if errors.As(err, &usage) {
		return exitUsage
	}
	return exitFailure
}
