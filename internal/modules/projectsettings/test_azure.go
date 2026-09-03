package projectsettings

import (
	"context"
	"fmt"
	"net/http"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
)

// AzureTestService implements TestService using the confirmed public REST API.
// Endpoint: GET/PATCH /{project}/_apis/test/resultretentionsettings?api-version=7.0
type AzureTestService struct {
	test *azure.Adapter
}

func NewAzureTestService(services azure.Services) *AzureTestService {
	return &AzureTestService{test: services.Test}
}

// testRetentionResponse maps the confirmed test/resultretentionsettings API response fields.
type testRetentionResponse struct {
	// AutomatedResultsRetentionDuration: days to keep automated test run results
	// when not associated with a pipeline (-1 = keep forever).
	AutomatedResultsRetentionDuration int `json:"automatedResultsRetentionDuration"`
	// ManualResultsRetentionDuration: days to keep manual test run results (-1 = keep forever).
	ManualResultsRetentionDuration int `json:"manualResultsRetentionDuration"`
}

func (s *AzureTestService) ReadTestRetention(ctx context.Context, project string) (config.TestRetentionConfig, error) {
	if s == nil || s.test == nil {
		return config.TestRetentionConfig{}, fmt.Errorf("test adapter is required")
	}
	var resp testRetentionResponse
	if err := s.test.Do(ctx, azure.Request{
		Project: project,
		Path:    "resultretentionsettings",
	}, &resp); err != nil {
		return config.TestRetentionConfig{}, fmt.Errorf("read test retention settings: %w", err)
	}
	return config.TestRetentionConfig{
		Retention: config.TestRetention{
			AutomatedRunDays: resp.AutomatedResultsRetentionDuration,
			ManualRunDays:    resp.ManualResultsRetentionDuration,
		},
	}, nil
}

func (s *AzureTestService) SetTestRetention(ctx context.Context, project string, cfg config.TestRetentionConfig) error {
	if s == nil || s.test == nil {
		return fmt.Errorf("test adapter is required")
	}
	payload := testRetentionResponse{
		AutomatedResultsRetentionDuration: cfg.Retention.AutomatedRunDays,
		ManualResultsRetentionDuration:    cfg.Retention.ManualRunDays,
	}
	if err := s.test.Do(ctx, azure.Request{
		Project: project,
		Method:  http.MethodPatch,
		Path:    "resultretentionsettings",
		Body:    payload,
	}, nil); err != nil {
		return fmt.Errorf("set test retention settings: %w", err)
	}
	return nil
}
