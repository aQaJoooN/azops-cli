package cli

import (
	"errors"
	"net/url"
	"os"
	"strings"

	"azops-cli/internal/domain"
)

const (
	azureURLEnvironment = "AZOPS_AZURE_URL"
	azurePATEnvironment = "AZOPS_AZURE_PAT"
)

// EnvironmentLookup reads an environment variable and reports whether it exists.
type EnvironmentLookup func(string) (string, bool)

// Connection contains validated Azure DevOps connection input.
type Connection struct {
	URL *url.URL
	PAT string
}

// ResolveConnection resolves and validates URL and PAT input without connecting.
func ResolveConnection(optionURL string, lookup EnvironmentLookup) (Connection, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	rawURL := strings.TrimSpace(optionURL)
	if rawURL == "" {
		rawURL, _ = lookup(azureURLEnvironment)
		rawURL = strings.TrimSpace(rawURL)
	}
	if rawURL == "" {
		return Connection{}, connectionError("Azure DevOps Server URL is required", nil)
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		if err == nil {
			err = errors.New("URL must include a scheme and host")
		}
		return Connection{}, connectionError("invalid Azure DevOps Server URL", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return Connection{}, connectionError("invalid Azure DevOps Server URL", errors.New("URL scheme must be http or https"))
	}

	pat, _ := lookup(azurePATEnvironment)
	if strings.TrimSpace(pat) == "" {
		return Connection{}, connectionError("Azure DevOps PAT is required in AZOPS_AZURE_PAT", nil)
	}
	return Connection{URL: parsedURL, PAT: pat}, nil
}

func connectionError(message string, err error) error {
	return &domain.ConnectionError{Message: message, Err: err}
}
