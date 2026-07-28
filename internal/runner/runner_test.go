package runner

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"azops-cli/internal/domain"
)

type recordingModule struct {
	id         domain.ModuleID
	component  domain.ComponentPath
	plan       domain.Plan
	planErr    error
	apply      domain.ApplyResult
	applyErr   error
	planFn     func()
	applyFn    func()
	applyCalls atomic.Int32
}

func (m *recordingModule) ID() domain.ModuleID             { return m.id }
func (m *recordingModule) Component() domain.ComponentPath { return m.component }
func (m *recordingModule) Plan(context.Context, domain.ModuleInput) (domain.Plan, error) {
	if m.planFn != nil {
		m.planFn()
	}
	return m.plan, m.planErr
}
func (m *recordingModule) Apply(context.Context, domain.Plan) (domain.ApplyResult, error) {
	m.applyCalls.Add(1)
	if m.applyFn != nil {
		m.applyFn()
	}
	return m.apply, m.applyErr
}

func module(id string) *recordingModule {
	return &recordingModule{id: domain.ModuleID(id), component: domain.ComponentPath("test." + id), plan: domain.Plan{Module: domain.ModuleID(id), Component: domain.ComponentPath("test." + id)}}
}

func TestRunWaitsForConcurrentSiblingsAndStopsAfterFailure(t *testing.T) {
	a, b, later := module("a"), module("b"), module("later")
	aStarted, bStarted := make(chan struct{}), make(chan struct{})
	aRelease, bRelease, bDone := make(chan struct{}), make(chan struct{}), make(chan struct{})

	a.planFn = func() { close(aStarted); <-bStarted; <-aRelease }
	b.planFn = func() { close(bStarted); <-aStarted; <-bRelease; close(bDone) }
	a.planErr = errors.New("plan failed")
	later.planFn = func() { t.Error("later stage started after failure") }

	done := make(chan domain.FinalResult, 1)
	go func() {
		done <- New().Run(context.Background(), domain.ExecutionGraph{Stages: []domain.ExecutionStage{
			{Number: 1, Modules: []domain.Module{a, b}},
			{Number: 2, Modules: []domain.Module{later}},
		}}, domain.ModuleInput{}, RunOptions{})
	}()
	<-aStarted
	<-bStarted
	close(aRelease)
	select {
	case <-done:
		t.Fatal("Run returned before current-stage sibling completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(bRelease)
	<-bDone
	result := <-done

	if result.Success || result.Failed != 1 || result.Unchanged != 1 || len(result.Results) != 2 {
		t.Fatalf("result = %#v, want one failed and one unchanged current-stage result", result)
	}
	if got := []domain.ModuleID{result.Results[0].Module, result.Results[1].Module}; !reflect.DeepEqual(got, []domain.ModuleID{"a", "b"}) {
		t.Fatalf("result order = %v, want graph order", got)
	}
}

func TestRunClassifiesPlansAppliesAndDryRun(t *testing.T) {
	unchanged, changed, planned := module("unchanged"), module("changed"), module("planned")
	operation := domain.Operation{Kind: domain.OperationUpdate, Resource: "resource", Summary: "update resource"}
	changed.plan.Operations = []domain.Operation{operation}
	changed.apply.Changes = []domain.ChangeSummary{{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary}}
	planned.plan.Operations = []domain.Operation{operation}

	applyResult := New().Run(context.Background(), domain.ExecutionGraph{Stages: []domain.ExecutionStage{{Number: 1, Modules: []domain.Module{unchanged, changed}}}}, domain.ModuleInput{}, RunOptions{})
	if !applyResult.Success || applyResult.Unchanged != 1 || applyResult.Changed != 1 || changed.applyCalls.Load() != 1 || unchanged.applyCalls.Load() != 0 {
		t.Fatalf("apply result/calls = %#v, %d/%d", applyResult, unchanged.applyCalls.Load(), changed.applyCalls.Load())
	}

	dryResult := New().Run(context.Background(), domain.ExecutionGraph{Stages: []domain.ExecutionStage{{Number: 3, Modules: []domain.Module{planned}}}}, domain.ModuleInput{}, RunOptions{DryRun: true})
	if !dryResult.Success || dryResult.Planned != 1 || planned.applyCalls.Load() != 0 {
		t.Fatalf("dry-run result/apply calls = %#v, %d", dryResult, planned.applyCalls.Load())
	}
	if got := dryResult.Results[0].Changes; !reflect.DeepEqual(got, []domain.ChangeSummary{{Kind: operation.Kind, Resource: operation.Resource, Summary: operation.Summary}}) {
		t.Fatalf("planned changes = %#v", got)
	}
}

func TestRunStartsNextStageOnlyAfterSuccessfulStageCompletes(t *testing.T) {
	first, second := module("first"), module("second")
	release, firstDone := make(chan struct{}), make(chan struct{})
	first.planFn = func() { <-release; close(firstDone) }
	second.planFn = func() {
		select {
		case <-firstDone:
		default:
			t.Error("next stage started before prior stage completed")
		}
	}

	done := make(chan domain.FinalResult, 1)
	go func() {
		done <- New().Run(context.Background(), domain.ExecutionGraph{Stages: []domain.ExecutionStage{
			{Number: 1, Modules: []domain.Module{first}},
			{Number: 2, Modules: []domain.Module{second}},
		}}, domain.ModuleInput{}, RunOptions{})
	}()
	select {
	case <-done:
		t.Fatal("Run returned while the first stage was blocked")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	result := <-done
	if !result.Success || result.Unchanged != 2 || len(result.Results) != 2 {
		t.Fatalf("result = %#v, want two successful unchanged stages", result)
	}
}
