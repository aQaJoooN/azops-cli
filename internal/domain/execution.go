package domain

// ExecutionGraph contains ordered stages of concurrent modules.
type ExecutionGraph struct {
	Stages []ExecutionStage
}

// ExecutionStage contains modules eligible to run concurrently.
type ExecutionStage struct {
	Number  int
	Modules []Module
}

// Outcome is the terminal state of one module execution.
type Outcome string

const (
	OutcomeUnchanged Outcome = "unchanged"
	OutcomePlanned   Outcome = "planned"
	OutcomeChanged   Outcome = "changed"
	OutcomeFailed    Outcome = "failed"
	OutcomeSkipped   Outcome = "skipped"
)

// ChangeSummary is safe for human-readable reporting.
type ChangeSummary struct {
	Kind     OperationKind
	Resource string
	Summary  string
}

// ApplyResult describes mutations completed by a module.
type ApplyResult struct {
	Changes []ChangeSummary
}

// ModuleResult captures the complete result of one module.
type ModuleResult struct {
	Stage      int
	Module     ModuleID
	Component  ComponentPath
	Outcome    Outcome
	Changes    []ChangeSummary
	Warnings   []string
	SkipReason string
	Err        error
}

// FinalResult aggregates all completed module results.
type FinalResult struct {
	Results   []ModuleResult
	Success   bool
	Changed   int
	Unchanged int
	Planned   int
	Failed    int
	Skipped   int
}
