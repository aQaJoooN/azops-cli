package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"azops-cli/internal/domain"
)

const (
	defaultTimeout    = 30 * time.Second
	defaultErrorLimit = int64(4096)
)

// Request describes one Azure DevOps REST request.
type Request struct {
	Service        Service
	Project        string
	Method         string
	Path           string
	APIVersion     string
	SkipAPIVersion bool // when true, no api-version query param is added
	Query          url.Values
	Body           any
}

// Client sends authenticated requests to one Azure DevOps collection.
type Client struct {
	baseURL    *url.URL
	pat        string
	httpClient *http.Client
	errorLimit int64
}

type clientOptions struct {
	httpClient *http.Client
	timeout    time.Duration
	errorLimit int64
}

// Option configures a Client.
type Option func(*clientOptions)

// WithHTTPClient supplies the HTTP transport used by the client.
func WithHTTPClient(client *http.Client) Option {
	return func(options *clientOptions) { options.httpClient = client }
}

// WithTimeout sets the total timeout for each HTTP request.
func WithTimeout(timeout time.Duration) Option {
	return func(options *clientOptions) { options.timeout = timeout }
}

// WithErrorBodyLimit bounds the response text retained in API errors.
func WithErrorBodyLimit(limit int64) Option {
	return func(options *clientOptions) { options.errorLimit = limit }
}

// NewClient creates an authenticated Azure DevOps REST client.
func NewClient(baseURL, pat string, options ...Option) (*Client, error) {
	if pat == "" {
		return nil, &domain.ConnectionError{Message: "Azure DevOps PAT is required"}
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, &domain.ConnectionError{Message: "invalid Azure DevOps URL", Err: sanitizeError(err, pat)}
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.EscapedPath(), "/")

	settings := clientOptions{timeout: defaultTimeout, errorLimit: defaultErrorLimit}
	for _, option := range options {
		option(&settings)
	}
	if settings.timeout <= 0 || settings.errorLimit <= 0 {
		return nil, &domain.ConnectionError{Message: "Azure DevOps client timeout and error limit must be positive"}
	}
	if settings.httpClient == nil {
		settings.httpClient = &http.Client{}
	}
	copy := *settings.httpClient
	copy.Timeout = settings.timeout

	return &Client{baseURL: parsed, pat: pat, httpClient: &copy, errorLimit: settings.errorLimit}, nil
}

// Do sends a request and decodes a successful JSON response into output.
func (client *Client) Do(ctx context.Context, request Request, output any) error {
	httpRequest, err := client.newRequest(ctx, request)
	if err != nil {
		return err
	}
	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		return &domain.ConnectionError{Message: "Azure DevOps request failed", Err: sanitizeError(err, client.pat)}
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return client.apiError(response)
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		return &domain.ConnectionError{Message: "decode Azure DevOps response", Err: sanitizeError(err, client.pat)}
	}
	return nil
}

func (client *Client) newRequest(ctx context.Context, request Request) (*http.Request, error) {
	if request.Method == "" {
		request.Method = http.MethodGet
	}
	version := request.APIVersion
	if version == "" {
		version = request.Service.APIVersion
	}
	if version == "" && !request.SkipAPIVersion {
		return nil, &domain.ConnectionError{Message: "Azure DevOps API version is required"}
	}

	endpoint := *client.baseURL
	segments := append([]string{}, request.Service.Prefix...)
	if request.Service.Scope == ProjectScope {
		if request.Project == "" {
			return nil, &domain.ConnectionError{Message: "Azure DevOps project is required"}
		}
		segments = append([]string{request.Project}, segments...)
	}
	segments = append(segments, splitPath(request.Path)...)
	endpoint.Path = joinPath(endpoint.Path, segments)
	endpoint.RawPath = joinEscapedPath(client.baseURL.EscapedPath(), segments)
	query := cloneQuery(request.Query)
	if !request.SkipAPIVersion && version != "" {
		query.Set("api-version", version)
	}
	endpoint.RawQuery = query.Encode()

	var body io.Reader
	if request.Body != nil {
		encoded, err := json.Marshal(request.Body)
		if err != nil {
			return nil, &domain.ConnectionError{Message: "encode Azure DevOps request", Err: sanitizeError(err, client.pat)}
		}
		body = bytes.NewReader(encoded)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, endpoint.String(), body)
	if err != nil {
		return nil, &domain.ConnectionError{Message: "create Azure DevOps request", Err: sanitizeError(err, client.pat)}
	}
	httpRequest.SetBasicAuth("", client.pat)
	httpRequest.Header.Set("Accept", "application/json")
	if request.Body != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	return httpRequest, nil
}

func joinEscapedPath(base string, segments []string) string {
	parts := make([]string, 0, len(segments)+1)
	if trimmed := strings.Trim(base, "/"); trimmed != "" {
		parts = append(parts, strings.Split(trimmed, "/")...)
	}
	for _, segment := range segments {
		parts = append(parts, url.PathEscape(segment))
	}
	return "/" + strings.Join(parts, "/")
}
func (client *Client) apiError(response *http.Response) error {
	readLimit := client.errorLimit + int64(len(client.pat)) + 1
	body, readErr := io.ReadAll(io.LimitReader(response.Body, readLimit))
	truncated := int64(len(body)) > client.errorLimit
	message := strings.TrimSpace(strings.ReplaceAll(string(body), client.pat, "[REDACTED]"))
	if int64(len(message)) > client.errorLimit {
		message = strings.TrimSpace(message[:client.errorLimit])
	}
	if truncated {
		message += "…"
	}
	if readErr != nil && message == "" {
		message = "response body unavailable"
	}
	return &domain.APIError{
		StatusCode: response.StatusCode,
		RequestID:  response.Header.Get("X-TFS-Session"),
		Message:    message,
	}
}

func splitPath(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}

func joinPath(base string, segments []string) string {
	parts := make([]string, 0, len(segments)+1)
	if trimmed := strings.Trim(base, "/"); trimmed != "" {
		parts = append(parts, strings.Split(trimmed, "/")...)
	}
	parts = append(parts, segments...)
	return "/" + strings.Join(parts, "/")
}

func cloneQuery(source url.Values) url.Values {
	copy := make(url.Values, len(source)+1)
	for key, values := range source {
		copy[key] = append([]string(nil), values...)
	}
	return copy
}

func sanitizeError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("request canceled: %s", message)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("request timed out: %s", message)
	}
	return errors.New(message)
}
