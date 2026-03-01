package rbac

import (
	"errors"
	"sync"
)

// ErrRoleNotFound is returned when a requested role does not exist in the store.
var ErrRoleNotFound = errors.New("rbac: role not found")

// Store is the persistence layer for roles and subject role assignments.
type Store interface {
	// GetRole retrieves a role by name. Returns ErrRoleNotFound when absent.
	GetRole(name string) (Role, error)
	// GetSubjectRoles returns all role names directly assigned to a subject.
	GetSubjectRoles(subject string) ([]string, error)
	// AssignRole grants a role to a subject (idempotent).
	AssignRole(subject, role string) error
	// UnassignRole removes a role from a subject (no-op if not assigned).
	UnassignRole(subject, role string) error
	// AddRole persists a role definition, overwriting any previous definition
	// with the same name.
	AddRole(role Role) error
	// RemoveRole deletes a role by name.
	RemoveRole(name string) error
}

// MemoryStore is a thread-safe in-memory implementation of Store.
// It is suitable for testing and simple applications. For production,
// back the store with a database.
type MemoryStore struct {
	mu       sync.RWMutex
	roles    map[string]Role
	subjects map[string][]string // subject → assigned role names
}

// NewMemoryStore returns an initialised MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		roles:    make(map[string]Role),
		subjects: make(map[string][]string),
	}
}

func (s *MemoryStore) GetRole(name string) (Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[name]
	if !ok {
		return Role{}, ErrRoleNotFound
	}
	return r, nil
}

func (s *MemoryStore) GetSubjectRoles(subject string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.subjects[subject]
	out := make([]string, len(src))
	copy(out, src)
	return out, nil
}

func (s *MemoryStore) AssignRole(subject, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.subjects[subject] {
		if r == role {
			return nil // already assigned
		}
	}
	s.subjects[subject] = append(s.subjects[subject], role)
	return nil
}

func (s *MemoryStore) UnassignRole(subject, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	roles := s.subjects[subject]
	for i, r := range roles {
		if r == role {
			s.subjects[subject] = append(roles[:i], roles[i+1:]...)
			return nil
		}
	}
	return nil
}

func (s *MemoryStore) AddRole(role Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[role.Name] = role
	return nil
}

func (s *MemoryStore) RemoveRole(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, name)
	return nil
}
