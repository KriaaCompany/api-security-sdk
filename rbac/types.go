package rbac

import "fmt"

// Permission defines a single operation on a resource.
// Use "*" as a wildcard for either field to match anything.
type Permission struct {
	// Resource is the name of the protected resource (e.g. "posts", "users").
	Resource string
	// Action is the operation being performed (e.g. "read", "create", "delete").
	Action string
}

// String returns a "resource:action" representation of the permission.
func (p Permission) String() string {
	return fmt.Sprintf("%s:%s", p.Resource, p.Action)
}

// matches reports whether p covers the given resource and action,
// honouring "*" wildcards on either field.
func (p Permission) matches(resource, action string) bool {
	resourceOK := p.Resource == "*" || p.Resource == resource
	actionOK := p.Action == "*" || p.Action == action
	return resourceOK && actionOK
}

// Role is a named set of permissions that can be assigned to subjects.
type Role struct {
	// Name is the unique identifier for this role (e.g. "admin", "viewer").
	Name string
	// Parents lists role names whose permissions this role inherits transitively.
	Parents []string
	// Permissions are the access rights granted directly by this role.
	Permissions []Permission
}
