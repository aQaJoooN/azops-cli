package domain

// ComponentPath identifies a root or inner configuration component.
type ComponentPath string

// SelectionKind describes the scope requested by an apply command.
type SelectionKind string

const (
	SelectionAll       SelectionKind = "all"
	SelectionRoot      SelectionKind = "root"
	SelectionComponent SelectionKind = "component"
)

// Selection identifies the configuration scope to reconcile.
type Selection struct {
	Kind SelectionKind
	Path ComponentPath
}
