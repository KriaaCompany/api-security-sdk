// Package ginmw provides Gin-compatible middleware for the api-security-sdk.
// It bridges the SDK's JWT, RBAC, and audit packages with the Gin web framework.
//
// # JWT authentication
//
//	svc := jwt.New(jwt.WithHMAC(secret))
//	r.Use(ginmw.JWT(svc))
//
// # Verify-only (Auth0 / external IdP)
//
//	src := jwks.Auth0("myapp.auth0.com")
//	svc := jwt.New(jwt.WithJWKS(src.KeyFunc))
//	r.Use(ginmw.JWT(svc))
//
// # RBAC middleware
//
//	enforcer := rbac.New(store)
//	r.GET("/admin", ginmw.RequireRole(enforcer, "admin"), handler)
//	r.DELETE("/posts/:id", ginmw.RequirePermission(enforcer, "delete", "posts"), handler)
//
// # Scope checking (OAuth 2.0 / OIDC scopes)
//
//	r.GET("/profile", ginmw.ScopeChecker("read:profile"), handler)
package ginmw

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	jwtpkg "github.com/KriaaCompany/api-security-sdk/auth/jwt"
	"github.com/KriaaCompany/api-security-sdk/rbac"
)

// Context keys used to store values in gin.Context.
const (
	claimsKey  = "ginmw:claims"
	subjectKey = "ginmw:subject"
)

// JWT returns a Gin middleware that:
//  1. Extracts the Bearer token from the Authorization header.
//  2. Validates it via svc.Verify (supports JWKS, HMAC, RSA, ECDSA).
//  3. Stores the *jwt.Claims in the Gin context under "ginmw:claims".
//
// Requests without a valid token are rejected with 401. To make auth optional,
// do not use this middleware globally — instead apply it only to protected groups.
func JWT(svc *jwtpkg.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearer(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or malformed Authorization header",
			})
			return
		}

		claims, err := svc.Verify(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.Set(claimsKey, claims)
		c.Set(subjectKey, claims.Subject)
		c.Next()
	}
}

// RequireRole returns a middleware that rejects requests (403) unless the
// authenticated subject has at least one of the provided roles.
//
// Must be used after ginmw.JWT (or another middleware that sets the subject).
func RequireRole(enforcer *rbac.Enforcer, roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject := SubjectFrom(c)
		if subject == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthenticated",
			})
			return
		}

		for _, role := range roles {
			if enforcer.HasRole(subject, role) {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "forbidden: insufficient role",
		})
	}
}

// RequirePermission returns a middleware that rejects requests (403) unless
// the authenticated subject has permission to perform action on resource.
//
// Must be used after ginmw.JWT.
func RequirePermission(enforcer *rbac.Enforcer, action, resource string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject := SubjectFrom(c)
		if subject == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthenticated",
			})
			return
		}

		if !enforcer.Can(subject, action, resource) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "forbidden: " + action + " on " + resource + " not allowed",
			})
			return
		}

		c.Next()
	}
}

// ScopeChecker returns a middleware that verifies the JWT contains all of the
// required OAuth 2.0 / OIDC scopes. It inspects two standard claim shapes:
//
//   - "scope"  — a single space-delimited string (e.g. "read:users write:posts")
//   - "scopes" — a JSON array of strings (e.g. ["read:users","write:posts"])
//
// Both conventions are widely used; Auth0 uses "scope" (string), some OIDC
// providers use "scopes" (array). ScopeChecker handles either.
//
// Must be used after ginmw.JWT.
func ScopeChecker(required ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := ClaimsFrom(c)
		if claims == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthenticated",
			})
			return
		}

		granted := extractScopes(claims.Custom)
		for _, need := range required {
			if !hasScope(granted, need) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "forbidden: missing required scope: " + need,
				})
				return
			}
		}

		c.Next()
	}
}

// ClaimsFrom retrieves the *jwt.Claims stored by the JWT middleware.
// Returns nil if JWT middleware has not run or the token was invalid.
func ClaimsFrom(c *gin.Context) *jwtpkg.Claims {
	v, _ := c.Get(claimsKey)
	claims, _ := v.(*jwtpkg.Claims)
	return claims
}

// SubjectFrom retrieves the authenticated subject (sub claim) stored by the
// JWT middleware. Returns "" if JWT middleware has not run.
func SubjectFrom(c *gin.Context) string {
	sub, _ := c.Get(subjectKey)
	s, _ := sub.(string)
	return s
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func extractBearer(header string) string {
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return header[len(prefix):]
	}
	return ""
}

// extractScopes normalises both "scope" (string) and "scopes" ([]any) claim
// shapes into a flat slice of individual scope strings.
func extractScopes(custom map[string]any) []string {
	if custom == nil {
		return nil
	}

	// "scope": "read:users write:posts"
	if raw, ok := custom["scope"]; ok {
		if s, ok := raw.(string); ok {
			return strings.Fields(s)
		}
	}

	// "scopes": ["read:users", "write:posts"]
	if raw, ok := custom["scopes"]; ok {
		switch v := raw.(type) {
		case []string:
			return v
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
	}

	return nil
}

func hasScope(granted []string, need string) bool {
	for _, s := range granted {
		if s == need {
			return true
		}
	}
	return false
}
