package detector

import (
	"fmt"
	"strings"

	"azops-cli/internal/config"
	"azops-cli/internal/domain"
)

// Detector maps selections over present configuration to the fixed execution stages.
type Detector struct{ registry *Registry }

// New creates a Detector backed by registry.
func New(registry *Registry) *Detector { return &Detector{registry: registry} }

// Detect builds a graph containing only selected, present inner components.
func (d *Detector) Detect(selection domain.Selection, cfg config.Config) (domain.ExecutionGraph, []string, error) {
	if d == nil || d.registry == nil {
		return domain.ExecutionGraph{}, nil, usage("module registry is required")
	}
	selected, warnings, err := d.selectComponents(selection, cfg)
	if err != nil {
		return domain.ExecutionGraph{}, nil, err
	}

	stages := make(map[int][]domain.Module, 6)
	for _, item := range d.registry.ordered {
		if _, ok := selected[item.path]; !ok {
			continue
		}
		module := item.factory()
		if module == nil || module.Component() != item.path {
			return domain.ExecutionGraph{}, warnings, usage(fmt.Sprintf("invalid module factory for %q", item.path))
		}
		stages[item.stage] = append(stages[item.stage], module)
	}

	graph := domain.ExecutionGraph{}
	for stage := 1; stage <= 6; stage++ {
		if len(stages[stage]) > 0 {
			graph.Stages = append(graph.Stages, domain.ExecutionStage{Number: stage, Modules: stages[stage]})
		}
	}
	return graph, warnings, nil
}

func (d *Detector) selectComponents(selection domain.Selection, cfg config.Config) (map[domain.ComponentPath]struct{}, []string, error) {
	selected := make(map[domain.ComponentPath]struct{})
	switch selection.Kind {
	case domain.SelectionAll:
		if selection.Path != "" {
			return nil, nil, usage("all selection cannot contain a component path")
		}
		for _, item := range d.registry.ordered {
			if item.present(cfg) {
				selected[item.path] = struct{}{}
			}
		}
	case domain.SelectionRoot:
		root := string(selection.Path)
		if root != "general" && root != "projectsettings" && root != "pipelines" {
			return nil, nil, usage(fmt.Sprintf("unsupported root component %q", root))
		}
		for _, item := range d.registry.ordered {
			if strings.HasPrefix(string(item.path), root+".") && item.present(cfg) {
				selected[item.path] = struct{}{}
			}
		}
		if len(selected) == 0 {
			return selected, []string{fmt.Sprintf("root component %q contains no supported inner components", root)}, nil
		}
	case domain.SelectionComponent:
		item, ok := d.registry.byPath[selection.Path]
		if !ok {
			return nil, nil, usage(fmt.Sprintf("unsupported component path %q", selection.Path))
		}
		if !item.present(cfg) {
			return nil, nil, usage(fmt.Sprintf("selected component %q is absent from configuration", selection.Path))
		}
		selected[item.path] = struct{}{}
	default:
		return nil, nil, usage(fmt.Sprintf("unsupported selection kind %q", selection.Kind))
	}
	return selected, nil, nil
}

func usage(message string) error { return &domain.UsageError{Message: message} }
