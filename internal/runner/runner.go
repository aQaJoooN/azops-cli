package runner

import (
	"context"
	"errors"
	"sync"

	"azops-cli/internal/domain"
)

// RunOptions controls execution without changing the execution graph.
type RunOptions struct {
	DryRun bool
}

// Runner executes each graph stage in order.
type Runner struct{}

// New creates a Runner.
func New() *Runner { return &Runner{} }

// Run executes stage modules concurrently and stops before the next stage on failure.
func (r *Runner) Run(ctx context.Context, graph domain.ExecutionGraph, input domain.ModuleInput, options RunOptions) domain.FinalResult {
	final := domain.FinalResult{Success: true}
	for _, stage := range graph.Stages {
		results := runStage(ctx, stage, input, options)
		final.Results = append(final.Results, results...)
		failed := false
		for _, result := range results {
			count(&final, result.Outcome)
			failed = failed || result.Outcome == domain.OutcomeFailed
		}
		if failed {
			final.Success = false
			break
		}
	}
	return final
}

func runStage(ctx context.Context, stage domain.ExecutionStage, input domain.ModuleInput, options RunOptions) []domain.ModuleResult {
	results := make([]domain.ModuleResult, len(stage.Modules))
	var wg sync.WaitGroup
	wg.Add(len(stage.Modules))
	for index, module := range stage.Modules {
		go func() {
			defer wg.Done()
			results[index] = runModule(ctx, stage.Number, module, input, options)
		}()
	}
	wg.Wait()
	return results
}

func runModule(ctx context.Context, stage int, module domain.Module, input domain.ModuleInput, options RunOptions) domain.ModuleResult {
	result := domain.ModuleResult{Stage: stage}
	if module == nil {
		result.Outcome = domain.OutcomeFailed
		result.Err = errors.New("runner: nil module")
		return result
	}
	result.Module, result.Component = module.ID(), module.Component()
	plan, err := module.Plan(ctx, input)
	if err != nil {
		result.Outcome, result.Err = domain.OutcomeFailed, err
		return result
	}
	if len(plan.Operations) == 0 {
		result.Outcome = domain.OutcomeUnchanged
		return result
	}
	if options.DryRun {
		result.Outcome = domain.OutcomePlanned
		result.Changes = summaries(plan.Operations)
		return result
	}
	applied, err := module.Apply(ctx, plan)
	if err != nil {
		result.Outcome, result.Err = domain.OutcomeFailed, err
		result.Changes = applied.Changes
		return result
	}
	result.Outcome, result.Changes = domain.OutcomeChanged, applied.Changes
	return result
}

func summaries(operations []domain.Operation) []domain.ChangeSummary {
	changes := make([]domain.ChangeSummary, len(operations))
	for i, operation := range operations {
		changes[i] = domain.ChangeSummary{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary}
	}
	return changes
}

func count(final *domain.FinalResult, outcome domain.Outcome) {
	switch outcome {
	case domain.OutcomeChanged:
		final.Changed++
	case domain.OutcomeUnchanged:
		final.Unchanged++
	case domain.OutcomePlanned:
		final.Planned++
	case domain.OutcomeFailed:
		final.Failed++
	}
}
