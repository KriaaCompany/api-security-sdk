package jwt

import "sync"

// Blacklist is the interface for a token revocation store.
type Blacklist interface {
	// Revoke marks the token string as revoked.
	Revoke(token string) error
	// IsRevoked reports whether the token has been revoked.
	IsRevoked(token string) (bool, error)
}

// MemoryBlacklist is a thread-safe, in-memory Blacklist implementation.
// Revoked tokens are stored indefinitely. For production, prefer a
// Redis-backed implementation with TTL-based expiry.
type MemoryBlacklist struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
}

// NewMemoryBlacklist returns an initialised MemoryBlacklist.
func NewMemoryBlacklist() *MemoryBlacklist {
	return &MemoryBlacklist{revoked: make(map[string]struct{})}
}

// Revoke adds the token to the revocation set.
func (b *MemoryBlacklist) Revoke(token string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked[token] = struct{}{}
	return nil
}

// IsRevoked reports whether the token is in the revocation set.
func (b *MemoryBlacklist) IsRevoked(token string) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.revoked[token]
	return ok, nil
}
