// Package apikey provides API key generation, storage, and HTTP authentication.
//
// Keys are generated as prefixed, base62-encoded random strings (e.g.
// "sk_live_4Xy…"). Only a SHA-256 hash of the key is ever stored, so a
// compromised database cannot expose the plaintext keys.
//
// Quick start:
//
//	store := apikey.NewMemoryStore()
//	svc   := apikey.NewService(store)
//
//	// Issue a key (e.g. on account creation)
//	key, err := svc.Issue(apikey.IssueOptions{Name: "ci-pipeline", Prefix: "sk_live"})
//	fmt.Println(key.Plaintext) // show once, never store
//
//	// Authenticate HTTP requests
//	mux.Handle("/api/", apikey.Middleware(svc)(handler))
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Sentinel errors.
var (
	ErrInvalidKey  = errors.New("apikey: invalid or unrecognised key")
	ErrRevokedKey  = errors.New("apikey: key has been revoked")
	ErrExpiredKey  = errors.New("apikey: key has expired")
	ErrKeyNotFound = errors.New("apikey: key not found")
)

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Key is the full representation of an API key stored in the backend.
type Key struct {
	// ID is a unique opaque identifier (derived from the key hash).
	ID string
	// Hash is the hex-encoded SHA-256 of the plaintext key.
	Hash string
	// Name is a human-readable label (e.g. "ci-pipeline").
	Name string
	// Subject associates the key with a user or service (e.g. user ID).
	Subject string
	// Metadata holds arbitrary application data.
	Metadata map[string]any
	// CreatedAt is when the key was issued.
	CreatedAt time.Time
	// ExpiresAt is the optional expiry time. Nil means the key never expires.
	ExpiresAt *time.Time
	// Revoked is true when the key has been explicitly revoked.
	Revoked bool
}

// IsExpired reports whether the key has passed its expiry time.
func (k *Key) IsExpired() bool {
	return k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt)
}

// IssueOptions configures a newly issued key.
type IssueOptions struct {
	// Prefix is prepended to the plaintext key (e.g. "sk_live", "sk_test").
	// A separator "_" is added automatically between prefix and random part.
	Prefix string
	// Name is a human-readable label stored alongside the key hash.
	Name string
	// Subject associates the key with an entity (e.g. a user ID).
	Subject string
	// Metadata holds arbitrary key-value data to store with the key.
	Metadata map[string]any
	// ExpiresIn sets an optional TTL. Zero means the key never expires.
	ExpiresIn time.Duration
	// Length is the number of random base62 characters (default: 40).
	Length int
}

// IssuedKey is returned by Service.Issue. It holds both the plaintext key
// (shown to the user exactly once) and the stored Key record.
type IssuedKey struct {
	// Plaintext is the full key string to present to the user.
	// It is never stored internally — lose it and you lose the key.
	Plaintext string
	// Key is the stored record (without the plaintext).
	Key *Key
}

// ─── Service ─────────────────────────────────────────────────────────────────

// Service manages API key lifecycle.
type Service struct {
	store Store
}

// NewService creates a Service backed by the given Store.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// Issue generates a new API key, hashes it, and persists the record.
// The caller must present IssuedKey.Plaintext to the end user; it is not
// recoverable after this call returns.
func (s *Service) Issue(opts IssueOptions) (*IssuedKey, error) {
	length := opts.Length
	if length <= 0 {
		length = 40
	}
	random, err := generateBase62(length)
	if err != nil {
		return nil, fmt.Errorf("apikey: failed to generate key: %w", err)
	}

	plaintext := random
	if opts.Prefix != "" {
		plaintext = opts.Prefix + "_" + random
	}

	hash := hashKey(plaintext)
	k := &Key{
		ID:        hash[:16], // first 16 hex chars as a short ID
		Hash:      hash,
		Name:      opts.Name,
		Subject:   opts.Subject,
		Metadata:  opts.Metadata,
		CreatedAt: time.Now(),
	}
	if opts.ExpiresIn > 0 {
		t := time.Now().Add(opts.ExpiresIn)
		k.ExpiresAt = &t
	}

	if err := s.store.Save(k); err != nil {
		return nil, err
	}
	return &IssuedKey{Plaintext: plaintext, Key: k}, nil
}

// Verify checks a plaintext key string and returns the stored Key record.
// Returns an error if the key is invalid, revoked, or expired.
func (s *Service) Verify(plaintext string) (*Key, error) {
	hash := hashKey(plaintext)
	k, err := s.store.GetByHash(hash)
	if err != nil {
		return nil, ErrInvalidKey
	}
	// Constant-time comparison guards against timing attacks on the hash lookup.
	if subtle.ConstantTimeCompare([]byte(k.Hash), []byte(hash)) != 1 {
		return nil, ErrInvalidKey
	}
	if k.Revoked {
		return nil, ErrRevokedKey
	}
	if k.IsExpired() {
		return nil, ErrExpiredKey
	}
	return k, nil
}

// Revoke marks the key with the given ID as revoked.
func (s *Service) Revoke(id string) error {
	return s.store.Revoke(id)
}

// ─── HTTP middleware ──────────────────────────────────────────────────────────

type apikeyContextKey struct{}

// Middleware returns an HTTP middleware that authenticates requests via an API
// key. The key is read from the Authorization header ("Bearer <key>") or the
// X-API-Key header. On success, the Key record is stored in the request context.
func Middleware(svc *Service, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	cfg := middlewareCfg{onError: defaultErrHandler}
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractKey(r)
			if raw == "" {
				cfg.onError(w, r, ErrInvalidKey)
				return
			}
			k, err := svc.Verify(raw)
			if err != nil {
				cfg.onError(w, r, err)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), apikeyContextKey{}, k))
			next.ServeHTTP(w, r)
		})
	}
}

// KeyFrom retrieves the authenticated Key from the request context.
// Returns nil when no key is present.
func KeyFrom(ctx context.Context) *Key {
	k, _ := ctx.Value(apikeyContextKey{}).(*Key)
	return k
}

// SubjectFrom returns the Subject field of the key stored in the context,
// or an empty string when absent.
func SubjectFrom(ctx context.Context) string {
	if k := KeyFrom(ctx); k != nil {
		return k.Subject
	}
	return ""
}

type middlewareCfg struct {
	onError func(http.ResponseWriter, *http.Request, error)
}

// MiddlewareOption configures apikey middleware behaviour.
type MiddlewareOption func(*middlewareCfg)

// WithErrorHandler replaces the default 401 error response handler.
func WithErrorHandler(fn func(http.ResponseWriter, *http.Request, error)) MiddlewareOption {
	return func(c *middlewareCfg) { c.onError = fn }
}

func extractKey(r *http.Request) string {
	if v := r.Header.Get("X-API-Key"); v != "" {
		return v
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if strings.HasPrefix(auth, prefix) {
		return strings.TrimPrefix(auth, prefix)
	}
	return ""
}

func defaultErrHandler(w http.ResponseWriter, _ *http.Request, _ error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func hashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func generateBase62(length int) (string, error) {
	b := make([]byte, length)
	max := big.NewInt(int64(len(base62Chars)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = base62Chars[n.Int64()]
	}
	return string(b), nil
}
