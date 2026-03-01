package ratelimit

import (
	"sync"
	"time"
)

// Store is the backend for tracking request counts.
// Implement this interface to back the rate limiter with Redis, Memcached, etc.
type Store interface {
	// Inc atomically increments the counter for key within the given window and
	// returns the current count. The store must expire the key after window elapses.
	Inc(key string, window time.Duration) (count int64, err error)
	// Reset clears the counter for key immediately.
	Reset(key string) error
}

// ─── Sliding-window memory store ─────────────────────────────────────────────

// MemoryStore is a thread-safe, in-process Store implementation using a
// sliding-window counter algorithm. It is suitable for single-process
// deployments. For horizontally-scaled services use a shared store (e.g. Redis).
type MemoryStore struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// NewMemoryStore returns an initialised MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{buckets: make(map[string]*bucket)}
}

// bucket holds two fixed-window counters and the start time of the current window.
// The sliding-window estimate is:
//
//	rate ≈ prev * (1 − elapsed/window) + curr
//
// This is the same approximation used by Redis's sliding-window rate limiter.
type bucket struct {
	mu          sync.Mutex
	prev        int64
	curr        int64
	windowStart time.Time
	window      time.Duration
}

func (b *bucket) inc(now time.Time) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	elapsed := now.Sub(b.windowStart)
	switch {
	case elapsed >= 2*b.window:
		// Both windows are stale.
		b.prev = 0
		b.curr = 1
		b.windowStart = now
	case elapsed >= b.window:
		// Current window becomes previous; start a fresh current window.
		b.prev = b.curr
		b.curr = 1
		b.windowStart = b.windowStart.Add(b.window)
	default:
		b.curr++
	}

	// Sliding-window approximation.
	fraction := float64(b.window-elapsed) / float64(b.window)
	if fraction < 0 {
		fraction = 0
	}
	return int64(float64(b.prev)*fraction) + b.curr
}

func (s *MemoryStore) Inc(key string, window time.Duration) (int64, error) {
	s.mu.Lock()
	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{windowStart: time.Now(), window: window}
		s.buckets[key] = b
	}
	s.mu.Unlock()
	return b.inc(time.Now()), nil
}

func (s *MemoryStore) Reset(key string) error {
	s.mu.Lock()
	delete(s.buckets, key)
	s.mu.Unlock()
	return nil
}
