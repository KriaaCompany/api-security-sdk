// Package rbac provides Role-Based Access Control (RBAC) with role inheritance.
//
// Quick start:
//
//	store := rbac.NewMemoryStore()
//	store.AddRole(rbac.Role{
//	    Name: "editor",
//	    Parents: []string{"viewer"},
//	    Permissions: []rbac.Permission{{Resource: "posts", Action: "create"}},
//	})
//	store.AssignRole("alice", "editor")
//
//	e := rbac.New(store)
//	e.Can("alice", "create", "posts") // true
package rbac

import "errors"

// ErrPermissionDenied is returned by Enforce when access is not granted.
var ErrPermissionDenied = errors.New("rbac: permission denied")

// Enforcer evaluates access decisions using the configured Store.
type Enforcer struct {
	store Store
}

// New creates an Enforcer backed by the given Store.
func New(store Store) *Enforcer {
	return &Enforcer{store: store}
}

// Can reports whether the subject has permission to perform action on resource.
// Role inheritance is resolved transitively; cycles are guarded against.
func (e *Enforcer) Can(subject, action, resource string) bool {
	roleNames, err := e.store.GetSubjectRoles(subject)
	if err != nil {
		return false
	}
	visited := make(map[string]bool)
	for _, name := range roleNames {
		if e.roleHasPermission(name, action, resource, visited) {
			return true
		}
	}
	return false
}

// Enforce is like Can but returns ErrPermissionDenied when access is not granted.
func (e *Enforcer) Enforce(subject, action, resource string) error {
	if e.Can(subject, action, resource) {
		return nil
	}
	return ErrPermissionDenied
}

// RolesFor returns the role names directly assigned to subject.
func (e *Enforcer) RolesFor(subject string) ([]string, error) {
	return e.store.GetSubjectRoles(subject)
}

// HasRole reports whether subject has been directly assigned the given role name.
func (e *Enforcer) HasRole(subject, role string) bool {
	roles, err := e.store.GetSubjectRoles(subject)
	if err != nil {
		return false
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// roleHasPermission resolves inheritance recursively (up to 64 levels deep).
func (e *Enforcer) roleHasPermission(name, action, resource string, visited map[string]bool) bool {
	if visited[name] || len(visited) > 64 {
		return false // cycle / depth guard
	}
	visited[name] = true

	role, err := e.store.GetRole(name)
	if err != nil {
		return false
	}
	for _, perm := range role.Permissions {
		if perm.matches(resource, action) {
			return true
		}
	}
	for _, parent := range role.Parents {
		if e.roleHasPermission(parent, action, resource, visited) {
			return true
		}
	}
	return false
}
