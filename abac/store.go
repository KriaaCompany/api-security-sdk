package abac

import (
	"errors"
	"sort"
	"sync"
)

// ErrPolicyNotFound is returned when a requested policy does not exist.
var ErrPolicyNotFound = errors.New("abac: policy not found")

// PolicyStore persists and retrieves access policies.
type PolicyStore interface {
	// AddPolicy stores a policy. If a policy with the same ID already exists
	// it is overwritten.
	AddPolicy(policy Policy) error
	// RemovePolicy removes the policy with the given ID.
	RemovePolicy(id string) error
	// Policies returns all stored policies ordered by descending Priority.
	Policies() ([]Policy, error)
}

// MemoryStore is a thread-safe in-memory PolicyStore.
type MemoryStore struct {
	mu       sync.RWMutex
	policies map[string]Policy
}

// NewMemoryStore returns an initialised MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{policies: make(map[string]Policy)}
}

func (s *MemoryStore) AddPolicy(policy Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.ID] = policy
	return nil
}

func (s *MemoryStore) RemovePolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[id]; !ok {
		return ErrPolicyNotFound
	}
	delete(s.policies, id)
	return nil
}

func (s *MemoryStore) Policies() ([]Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	// Stable sort: higher priority first. Ties preserve insertion order.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Priority > out[j].Priority
	})
	return out, nil
}
