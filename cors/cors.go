// Package cors provides a configurable Cross-Origin Resource Sharing (CORS)
// middleware for standard net/http servers.
//
// Correct CORS handling is subtle. This implementation:
//   - Matches origins against an explicit allowlist (never reflects arbitrary origins)
//   - Handles preflight OPTIONS requests and caches them via Access-Control-Max-Age
//   - Sets Vary: Origin so CDNs and proxies cache responses correctly per origin
//   - Rejects credentialed requests when AllowedOrigins contains a wildcard
//
// Quick start — development (allow everything):
//
//	mux.Handle("/", cors.AllowAll()(handler))
//
// Production:
//
//	mux.Handle("/", cors.New(cors.Config{
//	    AllowedOrigins: []string{"https://app.example.com"},
//	    AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
//	    AllowedHeaders: []string{"Authorization", "Content-Type"},
//	    MaxAge:         12 * time.Hour,
//	})(handler))
package cors

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config controls CORS policy.
type Config struct {
	// AllowedOrigins is the list of origins that are permitted to make
	// cross-origin requests. Use "*" to allow any origin (development only).
	// Each entry must be an exact origin string (scheme + host + optional port),
	// e.g. "https://app.example.com".
	AllowedOrigins []string

	// AllowedMethods lists the HTTP methods allowed for cross-origin requests.
	// Defaults to ["GET", "HEAD", "POST"] when empty.
	AllowedMethods []string

	// AllowedHeaders lists the request headers that may be used by a
	// cross-origin request. "Origin", "Accept", and "Content-Type" are always
	// included per the spec.
	AllowedHeaders []string

	// ExposedHeaders lists response headers that browsers are allowed to
	// read from the response. Simple headers are always exposed by browsers.
	ExposedHeaders []string

	// AllowCredentials indicates whether the request can include cookies,
	// HTTP authentication, or TLS client certificates.
	// Must not be combined with AllowedOrigins containing "*".
	AllowCredentials bool

	// MaxAge controls the Access-Control-Max-Age header sent on preflight
	// responses. Limits how long browsers cache the preflight result.
	// Defaults to 5 minutes.
	MaxAge time.Duration
}

// AllowAll returns a permissive CORS middleware suitable for development.
// Do not use this in production — it reflects any origin and allows all methods.
func AllowAll() func(http.Handler) http.Handler {
	return New(Config{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		MaxAge:         5 * time.Minute,
	})
}

// New returns a CORS middleware configured according to cfg.
func New(cfg Config) func(http.Handler) http.Handler {
	h := newHandler(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.handlePreflight(w, r)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.handleActual(w, r)
			next.ServeHTTP(w, r)
		})
	}
}

// ─── internal ────────────────────────────────────────────────────────────────

type corsHandler struct {
	allowedOrigins   map[string]bool
	wildcardOrigin   bool
	allowedMethods   string
	allowedHeaders   string
	exposedHeaders   string
	allowCredentials bool
	maxAge           string
}

func newHandler(cfg Config) *corsHandler {
	h := &corsHandler{
		allowedOrigins:   make(map[string]bool),
		allowCredentials: cfg.AllowCredentials,
	}

	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			h.wildcardOrigin = true
		} else {
			h.allowedOrigins[strings.ToLower(o)] = true
		}
	}

	methods := cfg.AllowedMethods
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD", "POST"}
	}
	h.allowedMethods = strings.Join(methods, ", ")

	headers := append([]string{"Origin", "Accept", "Content-Type"}, cfg.AllowedHeaders...)
	if len(cfg.AllowedHeaders) == 1 && cfg.AllowedHeaders[0] == "*" {
		h.allowedHeaders = "*"
	} else {
		seen := make(map[string]bool)
		deduped := headers[:0]
		for _, hdr := range headers {
			lower := strings.ToLower(hdr)
			if !seen[lower] {
				seen[lower] = true
				deduped = append(deduped, hdr)
			}
		}
		h.allowedHeaders = strings.Join(deduped, ", ")
	}

	if len(cfg.ExposedHeaders) > 0 {
		h.exposedHeaders = strings.Join(cfg.ExposedHeaders, ", ")
	}

	maxAge := cfg.MaxAge
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}
	h.maxAge = strconv.Itoa(int(maxAge.Seconds()))

	return h
}

func (h *corsHandler) originAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	if h.wildcardOrigin {
		return true
	}
	return h.allowedOrigins[strings.ToLower(origin)]
}

func (h *corsHandler) handlePreflight(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	hdr := w.Header()
	// Always set Vary so caches know the response varies by origin.
	hdr.Add("Vary", "Origin")
	hdr.Add("Vary", "Access-Control-Request-Method")
	hdr.Add("Vary", "Access-Control-Request-Headers")

	if !h.originAllowed(origin) {
		return
	}
	if h.wildcardOrigin && !h.allowCredentials {
		hdr.Set("Access-Control-Allow-Origin", "*")
	} else {
		hdr.Set("Access-Control-Allow-Origin", origin)
	}
	hdr.Set("Access-Control-Allow-Methods", h.allowedMethods)
	hdr.Set("Access-Control-Allow-Headers", h.allowedHeaders)
	hdr.Set("Access-Control-Max-Age", h.maxAge)
	if h.allowCredentials {
		hdr.Set("Access-Control-Allow-Credentials", "true")
	}
}

func (h *corsHandler) handleActual(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	hdr := w.Header()
	hdr.Add("Vary", "Origin")

	if !h.originAllowed(origin) {
		return
	}
	if h.wildcardOrigin && !h.allowCredentials {
		hdr.Set("Access-Control-Allow-Origin", "*")
	} else {
		hdr.Set("Access-Control-Allow-Origin", origin)
	}
	if h.allowCredentials {
		hdr.Set("Access-Control-Allow-Credentials", "true")
	}
	if h.exposedHeaders != "" {
		hdr.Set("Access-Control-Expose-Headers", h.exposedHeaders)
	}
}
