package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// EnableDisable represents an enabled or disabled feature.
type EnableDisable string

const (
	Enable  EnableDisable = "enable"
	Disable EnableDisable = "disable"
)

func (v *EnableDisable) UnmarshalYAML(node *yaml.Node) error {
	return decodeEnum(node, v, map[string]EnableDisable{"enable": Enable, "disable": Disable})
}

// OnOff represents a binary project setting.
type OnOff string

const (
	On  OnOff = "on"
	Off OnOff = "off"
)

func (v *OnOff) UnmarshalYAML(node *yaml.Node) error {
	return decodeEnum(node, v, map[string]OnOff{"on": On, "off": Off})
}

// AccessValue is an Azure DevOps permission state.
type AccessValue string

const (
	AccessAllow  AccessValue = "Allow"
	AccessDeny   AccessValue = "Deny"
	AccessNotSet AccessValue = "Not_Set"
)

var accessValues = map[string]AccessValue{
	"Allow": AccessAllow, "Deny": AccessDeny, "Not_Set": AccessNotSet,
}

func (v *AccessValue) UnmarshalYAML(node *yaml.Node) error {
	return decodeEnum(node, v, accessValues)
}

// Role is a supported Azure DevOps resource role.
type Role string

const (
	RoleAdministrator Role = "Administrator"
	RoleAdmin         Role = "Admin"
	RoleCreator       Role = "Creator"
	RoleUser          Role = "User"
	RoleReader        Role = "Reader"
)

var roles = map[string]Role{
	"Administrator": RoleAdministrator,
	"Admin":         RoleAdmin,
	"Creator":       RoleCreator,
	"User":          RoleUser,
	"Reader":        RoleReader,
}

func (v *Role) UnmarshalYAML(node *yaml.Node) error {
	return decodeEnum(node, v, roles)
}

func decodeEnum[T ~string](node *yaml.Node, target *T, allowed map[string]T) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: expected scalar value", node.Line)
	}
	value, ok := allowed[node.Value]
	if !ok {
		return fmt.Errorf("line %d: unsupported value %q", node.Line, node.Value)
	}
	*target = value
	return nil
}
