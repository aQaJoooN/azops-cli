package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"azops-cli/internal/domain"
)

const MissingSecretWarning = "no secret file found; continuing with empty secrets"

type LoadOptions struct {
	ConfigPath string
	SecretPath string
	WorkingDir string
}

type LoadedInputs struct {
	Config     Config
	Secrets    Secrets
	ConfigPath string
	SecretPath string
	Warnings   []string
}

type Loader struct {
	LookupEnv func(string) string
}

func (l Loader) Load(ctx context.Context, options LoadOptions) (LoadedInputs, error) {
	if err := ctx.Err(); err != nil {
		return LoadedInputs{}, err
	}
	lookupEnv := l.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.Getenv
	}
	workingDir := options.WorkingDir
	if workingDir == "" {
		workingDir = "."
	}

	configPath, err := discoverRequired(options.ConfigPath, lookupEnv("AZOPS_CONFIG_FILE"), workingDir, "config")
	if err != nil {
		return LoadedInputs{}, err
	}
	var cfg Config
	if err := decodeFile(configPath, &cfg); err != nil {
		return LoadedInputs{}, err
	}

	loaded := LoadedInputs{Config: cfg, ConfigPath: configPath}
	secretPath, found, err := discoverOptional(options.SecretPath, lookupEnv("AZOPS_SECRET_FILE"), workingDir, "secret")
	if err != nil {
		return LoadedInputs{}, err
	}
	if !found {
		loaded.Warnings = []string{MissingSecretWarning}
		return loaded, nil
	}
	if err := decodeFile(secretPath, &loaded.Secrets); err != nil {
		return LoadedInputs{}, err
	}
	loaded.SecretPath = secretPath
	return loaded, nil
}

func discoverRequired(cliPath, envPath, workingDir, baseName string) (string, error) {
	path, found, err := discoverOptional(cliPath, envPath, workingDir, baseName)
	if err != nil {
		return "", err
	}
	if !found {
		return "", &domain.DiscoveryError{Path: filepath.Join(workingDir, baseName+".yaml"), Err: errors.New("no input file candidate exists")}
	}
	return path, nil
}

func discoverOptional(cliPath, envPath, workingDir, baseName string) (string, bool, error) {
	if cliPath != "" {
		return requireReadable(cliPath)
	}
	if envPath != "" {
		return requireReadable(envPath)
	}
	for _, extension := range []string{".yaml", ".yml"} {
		path := filepath.Join(workingDir, baseName+extension)
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, true, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", false, &domain.DiscoveryError{Path: path, Err: err}
		}
	}
	return "", false, nil
}

func requireReadable(path string) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, &domain.DiscoveryError{Path: path, Err: err}
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return "", false, &domain.DiscoveryError{Path: path, Err: statErr}
	}
	if closeErr != nil {
		return "", false, &domain.DiscoveryError{Path: path, Err: closeErr}
	}
	if info.IsDir() {
		return "", false, &domain.DiscoveryError{Path: path, Err: errors.New("path is a directory")}
	}
	return path, true, nil
}
