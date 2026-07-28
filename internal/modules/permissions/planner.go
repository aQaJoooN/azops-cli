package permissions

import (
	"fmt"
	"sort"

	"azops-cli/internal/config"
)

// AccessBit identifies one permission's Azure DevOps security bit.
type AccessBit uint32

// AccessChange is one required access-bit assignment.
type AccessChange struct {
	Permission config.PermissionName
	Bit        AccessBit
	Principal  Principal
	Current    config.AccessValue
	Desired    config.AccessValue
}

// RoleChange is one required resource-role assignment.
type RoleChange struct {
	Principal Principal
	Current   config.Role
	Desired   config.Role
}

func PlanAccess(assignments config.AccessAssignments, bits map[config.PermissionName]AccessBit, principals map[config.GroupSelector][]Principal, current map[string]map[AccessBit]config.AccessValue) ([]AccessChange, error) {
	changes := make([]AccessChange, 0)
	seen := make(map[string]config.AccessValue)
	for permission, byAccess := range assignments {
		bit, exists := bits[permission]
		if !exists || bit == 0 {
			return nil, fmt.Errorf("permission %q cannot be resolved", permission)
		}
		for desired, selectors := range byAccess {
			if !validAccess(desired) {
				return nil, fmt.Errorf("permission %q has unsupported access value %q", permission, desired)
			}
			for _, selector := range selectors {
				resolved, exists := principals[selector]
				if !exists || len(resolved) == 0 {
					return nil, fmt.Errorf("permission %q group selector %q cannot be resolved", permission, selector)
				}
				for _, principal := range resolved {
					key := fmt.Sprintf("%s\x00%d", principal.Descriptor, bit)
					if previous, exists := seen[key]; exists {
						if previous != desired {
							return nil, fmt.Errorf("permission %q assigns both %q and %q to group %q", permission, previous, desired, principal.Name)
						}
						continue
					}
					seen[key] = desired
					currentValue := config.AccessNotSet
					if values := current[principal.Descriptor]; values != nil {
						if value, exists := values[bit]; exists {
							if !validAccess(value) {
								return nil, fmt.Errorf("permission %q has unsupported current access value %q", permission, value)
							}
							currentValue = value
						}
					}
					if currentValue != desired {
						changes = append(changes, AccessChange{permission, bit, principal, currentValue, desired})
					}
				}
			}
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Permission == changes[j].Permission {
			return changes[i].Principal.Descriptor < changes[j].Principal.Descriptor
		}
		return changes[i].Permission < changes[j].Permission
	})
	return changes, nil
}

func PlanRoles(assignments config.RoleAssignments, principals map[config.GroupSelector][]Principal, current map[string]config.Role, supported map[config.Role]struct{}) ([]RoleChange, error) {
	changes := make([]RoleChange, 0)
	seen := make(map[string]config.Role)
	for desired, selectors := range assignments {
		if _, exists := supported[desired]; !exists {
			return nil, fmt.Errorf("role %q is unsupported", desired)
		}
		for _, selector := range selectors {
			resolved, exists := principals[selector]
			if !exists || len(resolved) == 0 {
				return nil, fmt.Errorf("role %q group selector %q cannot be resolved", desired, selector)
			}
			for _, principal := range resolved {
				if previous, exists := seen[principal.Descriptor]; exists {
					if previous != desired {
						return nil, fmt.Errorf("group %q is assigned both roles %q and %q", principal.Name, previous, desired)
					}
					continue
				}
				seen[principal.Descriptor] = desired
				if existing, exists := current[principal.Descriptor]; !exists || existing != desired {
					changes = append(changes, RoleChange{Principal: principal, Current: existing, Desired: desired})
				}
			}
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Principal.Descriptor < changes[j].Principal.Descriptor })
	return changes, nil
}

func validAccess(value config.AccessValue) bool {
	return value == config.AccessAllow || value == config.AccessDeny || value == config.AccessNotSet
}
