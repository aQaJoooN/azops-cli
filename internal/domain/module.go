package domain

import "context"

// ModuleID uniquely identifies an Azure module.
type ModuleID string

// ModuleInput contains run-scoped dependencies and desired state.
type ModuleInput struct {
	DesiredState any
	SecretState  any
	Services     any
}

// Module plans and applies one component without parsing input files.
type Module interface {
	ID() ModuleID
	Component() ComponentPath
	Plan(context.Context, ModuleInput) (Plan, error)
	Apply(context.Context, Plan) (ApplyResult, error)
}

// OperationKind identifies a planned mutation category.
type OperationKind string

const (
	OperationCreate     OperationKind = "create"
	OperationUpdate     OperationKind = "update"
	OperationDelete     OperationKind = "delete"
	OperationPermission OperationKind = "permission"
)

// Operation is one deterministic action in a module plan.
type Operation struct {
	Kind     OperationKind
	Resource string
	Summary  string
	Payload  any
}

// Plan is the complete set of operations for one module.
type Plan struct {
	Module     ModuleID
	Component  ComponentPath
	Operations []Operation
	// SkipReason is set when the module is intentionally skipped (e.g. unsupported endpoint).
	// A non-empty value causes the runner to emit a warning and report OutcomeSkipped.
	SkipReason string
	// Warnings are informational messages about partially unsupported configuration.
	Warnings []string
}
