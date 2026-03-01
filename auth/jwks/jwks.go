// Package jwks provides a JWKS (JSON Web Key Set) key source for validating
// JWTs issued by external identity providers such as Auth0, AWS Cognito,
// Google, or any OIDC-compliant provider.
//
// The Source fetches public keys from a JWKS endpoint, caches them by key ID
// (kid), and automatically refreshes when an unknown kid is encountered —
// handling key rotation transparently.
//
// # Auth0 quick start
//
//	import (
//	    jwtpkg "github.com/KriaaCompany/api-security-sdk/auth/jwt"
//	    "github.com/KriaaCompany/api-security-sdk/auth/jwks"
//	)
//
//	src := jwks.Auth0("myapp.auth0.com")
//	svc := jwtpkg.New(jwtpkg.WithJWKS(src.KeyFunc))
//
//	claims, err := svc.Verify(tokenFromAuth0)
//
// # Generic OIDC provider
//
//	src := jwks.NewSource("https://accounts.google.com/.well-known/openid-configuration/jwks")
//	svc := jwtpkg.New(jwtpkg.WithJWKS(src.KeyFunc))
package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// ErrKIDNotFound is returned when the token's kid does not match any key in
// the JWKS after a fresh fetch.
var ErrKIDNotFound = errors.New("jwks: no key found for kid")

// ErrUnsupportedKeyType is returned for JWK entries with an unsupported kty.
var ErrUnsupportedKeyType = errors.New("jwks: unsupported key type (only RSA and EC supported)")

const (
	defaultCacheTTL        = 15 * time.Minute
	defaultMinRefreshDelay = 30 * time.Second // minimum gap between forced refreshes
	defaultHTTPTimeout     = 10 * time.Second
)

// Source fetches and caches public keys from a JWKS endpoint.
type Source struct {
	url     string
	mu      sync.RWMutex
	keys    map[string]any // kid → *rsa.PublicKey | *ecdsa.PublicKey
	fetchAt time.Time      // when cache was last populated

	cacheTTL        time.Duration
	minRefreshDelay time.Duration
	lastRefreshAt   time.Time // last forced refresh attempt (for rotation guard)
	httpClient      *http.Client
}

// Option configures a Source.
type Option func(*Source)

// WithCacheTTL sets how long fetched keys are cached before the next
// background refresh. Default: 15 minutes.
func WithCacheTTL(d time.Duration) Option {
	return func(s *Source) { s.cacheTTL = d }
}

// WithHTTPClient replaces the default HTTP client used to fetch the JWKS.
// Use this to set custom timeouts, TLS config, or a proxy.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Source) { s.httpClient = c }
}

// WithMinRefreshDelay sets the minimum time between forced key-rotation
// refreshes (triggered by an unknown kid). Default: 30 seconds.
func WithMinRefreshDelay(d time.Duration) Option {
	return func(s *Source) { s.minRefreshDelay = d }
}

// NewSource creates a Source that fetches keys from the given JWKS URL.
// Keys are fetched lazily on the first call to KeyFunc.
func NewSource(jwksURL string, opts ...Option) *Source {
	s := &Source{
		url:             jwksURL,
		keys:            make(map[string]any),
		cacheTTL:        defaultCacheTTL,
		minRefreshDelay: defaultMinRefreshDelay,
		httpClient:      &http.Client{Timeout: defaultHTTPTimeout},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Auth0 creates a Source for an Auth0 tenant.
//
//	src := jwks.Auth0("myapp.auth0.com")
//
// The domain may optionally include the "https://" scheme prefix; it is
// normalised automatically.
func Auth0(domain string, opts ...Option) *Source {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimRight(domain, "/")
	return NewSource(fmt.Sprintf("https://%s/.well-known/jwks.json", domain), opts...)
}

// KeyFunc is a github.com/golang-jwt/jwt/v5-compatible Keyfunc. Pass it
// directly to jwtpkg.WithJWKS:
//
//	svc := jwtpkg.New(jwtpkg.WithJWKS(src.KeyFunc))
func (s *Source) KeyFunc(token *gojwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)

	// Try the cache first.
	if key, ok := s.cachedKey(kid); ok {
		return key, nil
	}

	// Cache miss or expired — fetch a fresh JWKS.
	if err := s.refreshIfAllowed(); err != nil {
		return nil, err
	}

	// Try again after refresh.
	if key, ok := s.cachedKey(kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrKIDNotFound, kid)
}

// Preload fetches the JWKS immediately. Call this at startup to fail fast if
// the endpoint is unreachable, rather than failing on the first request.
func (s *Source) Preload() error {
	return s.fetch()
}

// ─── internal ─────────────────────────────────────────────────────────────────

func (s *Source) cachedKey(kid string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if time.Since(s.fetchAt) > s.cacheTTL {
		return nil, false // cache expired
	}
	if kid == "" {
		// No kid in token — return the first (and often only) key.
		for _, k := range s.keys {
			return k, true
		}
		return nil, false
	}
	k, ok := s.keys[kid]
	return k, ok
}

// refreshIfAllowed fetches a fresh JWKS, but not more often than
// minRefreshDelay to guard against DDOS via crafted tokens.
func (s *Source) refreshIfAllowed() error {
	s.mu.Lock()
	since := time.Since(s.lastRefreshAt)
	s.mu.Unlock()

	if since < s.minRefreshDelay {
		return fmt.Errorf("jwks: refusing to refresh: last attempt was %v ago (min %v)", since.Round(time.Second), s.minRefreshDelay)
	}
	return s.fetch()
}

func (s *Source) fetch() error {
	resp, err := s.httpClient.Get(s.url)
	if err != nil {
		return fmt.Errorf("jwks: fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: server returned %d for %s", resp.StatusCode, s.url)
	}

	var payload struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("jwks: failed to decode response: %w", err)
	}

	newKeys := make(map[string]any, len(payload.Keys))
	for _, raw := range payload.Keys {
		if raw.Use != "" && raw.Use != "sig" {
			continue // skip encryption keys
		}
		key, err := raw.toPublicKey()
		if err != nil {
			continue // skip unsupported key types gracefully
		}
		newKeys[raw.Kid] = key
	}

	s.mu.Lock()
	s.keys = newKeys
	s.fetchAt = time.Now()
	s.lastRefreshAt = time.Now()
	s.mu.Unlock()
	return nil
}

// ─── JWK parsing ──────────────────────────────────────────────────────────────

type rawJWK struct {
	Kty string `json:"kty"` // "RSA" | "EC"
	Kid string `json:"kid"`
	Use string `json:"use"` // "sig" | "enc"
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"` // "P-256" | "P-384" | "P-521"
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (r rawJWK) toPublicKey() (any, error) {
	switch r.Kty {
	case "RSA":
		return r.toRSA()
	case "EC":
		return r.toECDSA()
	default:
		return nil, ErrUnsupportedKeyType
	}
}

func (r rawJWK) toRSA() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(r.N)
	if err != nil {
		return nil, fmt.Errorf("jwks: invalid RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(r.E)
	if err != nil {
		return nil, fmt.Errorf("jwks: invalid RSA exponent: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func (r rawJWK) toECDSA() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch r.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jwks: unsupported EC curve %q", r.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(r.X)
	if err != nil {
		return nil, fmt.Errorf("jwks: invalid EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(r.Y)
	if err != nil {
		return nil, fmt.Errorf("jwks: invalid EC y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
