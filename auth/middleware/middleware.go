package middleware

import (
	"net/http"
	"strings"

	"github.com/KriaaCompany/api-security-sdk/auth/jwt"
)

// ErrorHandler is invoked when authentication fails. If not set, a default
// 401 JSON response is written.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

type middlewareConfig struct {
	onError ErrorHandler
}

// MiddlewareOption configures JWT middleware behaviour.
type MiddlewareOption func(*middlewareConfig)

// WithErrorHandler replaces the default 401 handler with a custom one.
func WithErrorHandler(h ErrorHandler) MiddlewareOption {
	return func(c *middlewareConfig) { c.onError = h }
}

// JWT returns an HTTP middleware that validates Bearer tokens in the
// Authorization header. On success, claims are stored in the request context
// and are accessible via ClaimsFrom / SubjectFrom.
//
// Usage:
//
//	mux.Handle("/api/", middleware.JWT(jwtSvc)(apiHandler))
func JWT(svc *jwt.Service, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	cfg := middlewareConfig{onError: defaultErrorHandler}
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := extractBearer(r)
			if err != nil {
				cfg.onError(w, r, err)
				return
			}
			claims, err := svc.Verify(token)
			if err != nil {
				cfg.onError(w, r, err)
				return
			}
			r = r.WithContext(WithClaims(r.Context(), claims))
			next.ServeHTTP(w, r)
		})
	}
}

// Optional is a variant of JWT that does not reject requests missing a token.
// When a valid token is present, claims are stored in the context as normal.
// When absent or invalid, the request passes through without claims.
//
// Useful for endpoints that behave differently for authenticated and
// anonymous users.
func Optional(svc *jwt.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token, err := extractBearer(r); err == nil {
				if claims, err := svc.Verify(token); err == nil {
					r = r.WithContext(WithClaims(r.Context(), claims))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth is a standalone middleware that rejects requests with no claims
// in the context. Pair it after Optional when you want a mixed auth chain.
func RequireAuth(onError ...ErrorHandler) func(http.Handler) http.Handler {
	handler := ErrorHandler(defaultErrorHandler)
	if len(onError) > 0 && onError[0] != nil {
		handler = onError[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ClaimsFrom(r.Context()) == nil {
				handler(w, r, jwt.ErrInvalidToken)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractBearer(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", jwt.ErrInvalidToken
	}
	token := strings.TrimPrefix(auth, prefix)
	if token == "" {
		return "", jwt.ErrInvalidToken
	}
	return token, nil
}

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, _ error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}
