// Package middleware provides standard net/http middleware for JWT authentication.
// It is framework-agnostic and works with any router that accepts http.Handler.
package middleware

import (
	"context"

	"github.com/KriaaCompany/api-security-sdk/auth/jwt"
)

type contextKey struct{}

// WithClaims stores JWT claims in the request context. This is called
// internally by the JWT middleware after successful token verification.
func WithClaims(ctx context.Context, claims *jwt.Claims) context.Context {
	return context.WithValue(ctx, contextKey{}, claims)
}

// ClaimsFrom retrieves JWT claims from the request context.
// Returns nil when no authenticated claims are present.
func ClaimsFrom(ctx context.Context) *jwt.Claims {
	c, _ := ctx.Value(contextKey{}).(*jwt.Claims)
	return c
}

// SubjectFrom returns the token subject (typically the user ID) from the
// context, or an empty string when no claims are present.
func SubjectFrom(ctx context.Context) string {
	if c := ClaimsFrom(ctx); c != nil {
		return c.Subject
	}
	return ""
}

// CustomClaimFrom retrieves a single custom claim value from the context by key.
// Returns nil when no claims are present or the key does not exist.
func CustomClaimFrom(ctx context.Context, key string) any {
	c := ClaimsFrom(ctx)
	if c == nil || c.Custom == nil {
		return nil
	}
	return c.Custom[key]
}
