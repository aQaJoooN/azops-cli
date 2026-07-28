package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func (a *AccessAssignments) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: permissions must be a mapping", node.Line)
	}
	result := make(AccessAssignments, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		name := PermissionName(node.Content[i].Value)
		if _, exists := result[name]; exists {
			return fmt.Errorf("line %d: duplicate permission %q", node.Content[i].Line, name)
		}
		accessNode := node.Content[i+1]
		if accessNode.Kind != yaml.MappingNode {
			return fmt.Errorf("line %d: permission %q must contain access mappings", accessNode.Line, name)
		}
		values := make(map[AccessValue][]GroupSelector, len(accessNode.Content)/2)
		for j := 0; j < len(accessNode.Content); j += 2 {
			access, err := parseAccessValue(accessNode.Content[j])
			if err != nil {
				return err
			}
			if _, exists := values[access]; exists {
				return fmt.Errorf("line %d: permission %q contains duplicate access %q", accessNode.Content[j].Line, name, access)
			}
			var groups []GroupSelector
			if err := accessNode.Content[j+1].Decode(&groups); err != nil {
				return fmt.Errorf("line %d: permission %q access %q: %w", accessNode.Content[j+1].Line, name, access, err)
			}
			values[access] = groups
		}
		result[name] = values
	}
	*a = result
	return nil
}

func (r *RoleAssignments) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: roles must be a mapping", node.Line)
	}
	result := make(RoleAssignments, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		role, err := parseRole(node.Content[i])
		if err != nil {
			return err
		}
		if _, exists := result[role]; exists {
			return fmt.Errorf("line %d: duplicate role %q", node.Content[i].Line, role)
		}
		var groups []GroupSelector
		if err := node.Content[i+1].Decode(&groups); err != nil {
			return fmt.Errorf("line %d: role %q: %w", node.Content[i+1].Line, role, err)
		}
		result[role] = groups
	}
	*r = result
	return nil
}

func parseAccessValue(node *yaml.Node) (AccessValue, error) {
	var value AccessValue
	if err := value.UnmarshalYAML(node); err != nil {
		return "", fmt.Errorf("invalid permission access value: %w", err)
	}
	return value, nil
}

func parseRole(node *yaml.Node) (Role, error) {
	var value Role
	if err := value.UnmarshalYAML(node); err != nil {
		return "", fmt.Errorf("invalid role: %w", err)
	}
	return value, nil
}
