package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"azops-cli/internal/domain"
)

// Reporter renders deterministic, redacted execution output.
type Reporter struct {
	writer   io.Writer
	redactor Redactor
}

// New creates a reporter that writes through redaction to writer.
func New(writer io.Writer, redactor Redactor) *Reporter {
	return &Reporter{writer: writer, redactor: redactor}
}

// Warning writes one redacted loader or execution warning.
func (r *Reporter) Warning(message string) error {
	return r.write("Warning: " + message + "\n")
}

// Render writes per-stage module results followed by aggregate counts.
func (r *Reporter) Render(final domain.FinalResult) error {
	// Sort stages while preserving detector/registry order within each stage.
	results := append([]domain.ModuleResult(nil), final.Results...)
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Stage < results[j].Stage
	})

	var output strings.Builder
	stage := -1
	for _, result := range results {
		if result.Stage != stage {
			stage = result.Stage
			fmt.Fprintf(&output, "Stage %d\n", stage)
		}
		fmt.Fprintf(&output, "  %s: %s\n", result.Component, result.Outcome)
		if result.Err != nil {
			fmt.Fprintf(&output, "    error: %s\n", result.Err)
		}
		changes := append([]domain.ChangeSummary(nil), result.Changes...)
		sort.SliceStable(changes, func(i, j int) bool {
			if changes[i].Summary != changes[j].Summary {
				return changes[i].Summary < changes[j].Summary
			}
			if changes[i].Resource != changes[j].Resource {
				return changes[i].Resource < changes[j].Resource
			}
			return changes[i].Kind < changes[j].Kind
		})
		label := "change"
		if result.Outcome == domain.OutcomePlanned {
			label = "planned"
		}
		for _, change := range changes {
			fmt.Fprintf(&output, "    %s: %s\n", label, change.Summary)
		}
	}
	status := "failed"
	if final.Success {
		status = "success"
	}
	fmt.Fprintf(&output, "Final: %s (changed=%d unchanged=%d planned=%d failed=%d)\n",
		status, final.Changed, final.Unchanged, final.Planned, final.Failed)
	return r.write(output.String())
}

func (r *Reporter) write(value string) error {
	if r == nil || r.writer == nil {
		return fmt.Errorf("report: nil writer")
	}
	_, err := io.WriteString(r.writer, r.redactor.Redact(value))
	return err
}
