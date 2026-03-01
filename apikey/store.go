package apikey

import "sync"

// Store persists API key records.
// Implement this interface to back the service with PostgreSQL, Redis, etc.
type Store interface {
	// Save persists a new key record.
	Save(k *Key) error
	// GetByHash retrieves a key by its SHA-256 hash. Returns ErrKeyNotFound
	// when absent.
	GetByHash(hash string) (*Key, error)
	// GetByID retrieves a key by its ID. Returns ErrKeyNotFound when absent.
	GetByID(id string) (*Key, error)
	// Revoke marks the key with the given ID as revoked.
	Revoke(id string) error
	// ListBySubject returns all keys associated with the given subject.
	ListBySubject(subject string) ([]*Key, error)
}

// MemoryStore is a thread-safe in-memory Store.
type MemoryStore struct {
	mu   sync.RWMutex
	byID map[string]*Key   // id → Key
	byH  map[string]string // hash → id
}

// NewMemoryStore returns an initialised MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID: make(map[string]*Key),
		byH:  make(map[string]string),
	}
}

func (s *MemoryStore) Save(k *Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *k
	s.byID[k.ID] = &clone
	s.byH[k.Hash] = k.ID
	return nil
}

func (s *MemoryStore) GetByHash(hash string) (*Key, error) {
	s.mu.RLock()
	id, ok := s.byH[hash]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrKeyNotFound
	}
	return s.GetByID(id)
}

func (s *MemoryStore) GetByID(id string) (*Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.byID[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	clone := *k
	return &clone, nil
}

func (s *MemoryStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[id]
	if !ok {
		return ErrKeyNotFound
	}
	k.Revoked = true
	return nil
}

func (s *MemoryStore) ListBySubject(subject string) ([]*Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Key
	for _, k := range s.byID {
		if k.Subject == subject {
			clone := *k
			out = append(out, &clone)
		}
	}
	return out, nil
}
