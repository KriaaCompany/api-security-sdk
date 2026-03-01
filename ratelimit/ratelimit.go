// Package ratelimit provides a sliding-window HTTP rate limiter middleware.
//
// Requests that exceed the limit receive a 429 Too Many Requests response with
// standard X-RateLimit-* and Retry-After headers. The rate-limiting key
// defaults to the client IP address but is fully configurable.
//
// Quick start:
//
//	store := ratelimit.NewMemoryStore()
//	limiter := ratelimit.New(store, ratelimit.Config{
//	    Limit:  100,
//	    Window: time.Minute,
//	})
//	mux.Handle("/api/", limiter(apiHandler))
package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Config configures a rate limiter middleware instance.
type Config struct {
	// Limit is the maximum number of requests allowed within Window.
	Limit int64
	// Window is the sliding-window duration (e.g. time.Minute).
	Window time.Duration
	// KeyFn derives the rate-limit key from the request.
	// Defaults to the client's remote IP address when nil.
	KeyFn func(r *http.Request) string
	// OnLimited is called when a request is rejected.
	// Defaults to a JSON 429 response when nil.
	OnLimited func(w http.ResponseWriter, r *http.Request, reset time.Time)
}

// New returns an HTTP middleware that enforces the given rate limit using store.
func New(store Store, cfg Config) func(http.Handler) http.Handler {
	if cfg.KeyFn == nil {
		cfg.KeyFn = remoteIP
	}
	if cfg.OnLimited == nil {
		cfg.OnLimited = defaultOnLimited
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := cfg.KeyFn(r)
			count, err := store.Inc(key, cfg.Window)
			reset := time.Now().Add(cfg.Window)

			remaining := cfg.Limit - count
			if remaining < 0 {
				remaining = 0
			}

			w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(cfg.Limit, 10))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))

			if err != nil || count > cfg.Limit {
				w.Header().Set("Retry-After", strconv.FormatInt(int64(cfg.Window.Seconds()), 10))
				cfg.OnLimited(w, r, reset)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ByIP returns a KeyFn that rate-limits per client IP address.
// This is the default KeyFn.
func ByIP(r *http.Request) string { return remoteIP(r) }

// BySubject returns a KeyFn that rate-limits per JWT subject stored in the
// request context. Falls back to the remote IP when no claims are present.
// Pair with auth/middleware.JWT to rate-limit authenticated users individually.
func BySubject(subjectFn func(r *http.Request) string) func(r *http.Request) string {
	return func(r *http.Request) string {
		if s := subjectFn(r); s != "" {
			return "subject:" + s
		}
		return remoteIP(r)
	}
}

// ByRoute returns a KeyFn that combines the client IP with the URL path,
// allowing different limits per route without separate middleware instances.
func ByRoute(r *http.Request) string {
	return remoteIP(r) + ":" + r.URL.Path
}

// Per returns a helper that expresses rates as "n requests per duration" and
// can be used to compute Limit/Window pairs more readably:
//
//	cfg := ratelimit.Per(100, time.Minute) // 100 req/min
func Per(requests int64, window time.Duration) Config {
	return Config{Limit: requests, Window: window}
}

func remoteIP(r *http.Request) string {
	// Prefer X-Forwarded-For when behind a trusted proxy.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first (leftmost) address — that is the original client.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func defaultOnLimited(w http.ResponseWriter, _ *http.Request, reset time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = fmt.Fprintf(w, `{"error":"rate limit exceeded","reset":%d}`, reset.Unix())
}
