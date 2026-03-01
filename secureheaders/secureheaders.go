// Package secureheaders provides an HTTP middleware that sets security-relevant
// response headers. Apply it once at the top of your middleware stack.
//
// Quick start — opinionated secure defaults:
//
//	mux.Handle("/", secureheaders.Strict()(handler))
//
// Custom configuration:
//
//	mux.Handle("/", secureheaders.New(secureheaders.Config{
//	    HSTS:            secureheaders.HSTSConfig{MaxAge: 365 * 24 * time.Hour, IncludeSubDomains: true},
//	    ContentTypeOpts: true,
//	    FrameOptions:    "DENY",
//	    ReferrerPolicy:  "strict-origin-when-cross-origin",
//	    CSP:             "default-src 'self'",
//	})(handler))
package secureheaders

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HSTSConfig configures the Strict-Transport-Security header.
type HSTSConfig struct {
	// MaxAge is how long browsers should remember to use HTTPS (default: 1 year).
	// Set to 0 to disable HSTS.
	MaxAge time.Duration
	// IncludeSubDomains extends HSTS to all subdomains.
	IncludeSubDomains bool
	// Preload signals intent to be included in browser HSTS preload lists.
	// Only set this if you have submitted your domain at https://hstspreload.org.
	Preload bool
}

// Config controls which security headers are emitted.
type Config struct {
	// HSTS configures the Strict-Transport-Security header.
	// Zero MaxAge disables the header (useful behind a TLS-terminating proxy).
	HSTS HSTSConfig

	// ContentTypeOpts emits "X-Content-Type-Options: nosniff" when true.
	ContentTypeOpts bool

	// FrameOptions controls the X-Frame-Options header.
	// Accepted values: "DENY", "SAMEORIGIN". Empty disables the header.
	FrameOptions string

	// XSSProtection emits "X-XSS-Protection: 1; mode=block" when true.
	// Note: modern browsers ignore this header in favour of CSP, but it is
	// harmless and helps with older browsers.
	XSSProtection bool

	// CSP is the full value for the Content-Security-Policy header.
	// Example: "default-src 'self'; img-src *; script-src 'self'"
	// Empty disables the header.
	CSP string

	// ReferrerPolicy sets the Referrer-Policy header.
	// Recommended: "strict-origin-when-cross-origin".
	// Empty disables the header.
	ReferrerPolicy string

	// PermissionsPolicy sets the Permissions-Policy header.
	// Example: "geolocation=(), microphone=(), camera=()"
	// Empty disables the header.
	PermissionsPolicy string

	// COEP sets the Cross-Origin-Embedder-Policy header.
	// Use "require-corp" to enable cross-origin isolation.
	COEP string

	// COOP sets the Cross-Origin-Opener-Policy header.
	// Use "same-origin" to prevent cross-origin window references.
	COOP string

	// CORP sets the Cross-Origin-Resource-Policy header.
	// Use "same-origin" or "same-site" to restrict resource sharing.
	CORP string

	// RemoveServerHeader strips the "Server" response header when true.
	RemoveServerHeader bool

	// RemovePoweredBy strips the "X-Powered-By" response header when true.
	RemovePoweredBy bool
}

// Strict returns a middleware with opinionated, production-grade security
// header defaults. Override individual fields via New if you need customisation.
//
// Headers set by Strict:
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - X-XSS-Protection: 1; mode=block
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Permissions-Policy: geolocation=(), microphone=(), camera=()
//   - Cross-Origin-Embedder-Policy: require-corp
//   - Cross-Origin-Opener-Policy: same-origin
//   - Cross-Origin-Resource-Policy: same-origin
//   - Removes Server and X-Powered-By headers
func Strict() func(http.Handler) http.Handler {
	return New(Config{
		HSTS:              HSTSConfig{MaxAge: 365 * 24 * time.Hour, IncludeSubDomains: true},
		ContentTypeOpts:   true,
		FrameOptions:      "DENY",
		XSSProtection:     true,
		ReferrerPolicy:    "strict-origin-when-cross-origin",
		PermissionsPolicy: "geolocation=(), microphone=(), camera=()",
		COEP:              "require-corp",
		COOP:              "same-origin",
		CORP:              "same-origin",
		RemoveServerHeader: true,
		RemovePoweredBy:    true,
	})
}

// New returns a middleware that applies the given security header configuration.
func New(cfg Config) func(http.Handler) http.Handler {
	headers := buildHeaders(cfg)
	remove := buildRemoveList(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			for k, v := range headers {
				h.Set(k, v)
			}
			for _, k := range remove {
				h.Del(k)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// buildHeaders pre-computes the header map from config so the hot path
// (per-request) is just a map iteration with no string formatting.
func buildHeaders(cfg Config) map[string]string {
	h := make(map[string]string, 12)

	if cfg.HSTS.MaxAge > 0 {
		var sb strings.Builder
		fmt.Fprintf(&sb, "max-age=%d", int(cfg.HSTS.MaxAge.Seconds()))
		if cfg.HSTS.IncludeSubDomains {
			sb.WriteString("; includeSubDomains")
		}
		if cfg.HSTS.Preload {
			sb.WriteString("; preload")
		}
		h["Strict-Transport-Security"] = sb.String()
	}
	if cfg.ContentTypeOpts {
		h["X-Content-Type-Options"] = "nosniff"
	}
	if cfg.FrameOptions != "" {
		h["X-Frame-Options"] = cfg.FrameOptions
	}
	if cfg.XSSProtection {
		h["X-XSS-Protection"] = "1; mode=block"
	}
	if cfg.CSP != "" {
		h["Content-Security-Policy"] = cfg.CSP
	}
	if cfg.ReferrerPolicy != "" {
		h["Referrer-Policy"] = cfg.ReferrerPolicy
	}
	if cfg.PermissionsPolicy != "" {
		h["Permissions-Policy"] = cfg.PermissionsPolicy
	}
	if cfg.COEP != "" {
		h["Cross-Origin-Embedder-Policy"] = cfg.COEP
	}
	if cfg.COOP != "" {
		h["Cross-Origin-Opener-Policy"] = cfg.COOP
	}
	if cfg.CORP != "" {
		h["Cross-Origin-Resource-Policy"] = cfg.CORP
	}
	return h
}

func buildRemoveList(cfg Config) []string {
	var remove []string
	if cfg.RemoveServerHeader {
		remove = append(remove, "Server")
	}
	if cfg.RemovePoweredBy {
		remove = append(remove, "X-Powered-By")
	}
	return remove
}
