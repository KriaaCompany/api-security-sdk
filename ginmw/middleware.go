// Package ginmw provides Gin-compatible middleware for the api-security-sdk.
// It bridges the SDK's JWT, RBAC, and audit packages with the Gin web framework.
//
// # JWT authentication
//
//	svc := jwt.New(jwt.WithHMAC(secret))
//	r.Use(ginmw.JWT(svc))
//
// # JWT with custom claims extraction and WebSocket fallback
//
//	extractor := ginmw.WithClaimsExtractor(func(c *gin.Context, cl *jwt.Claims) {
//	    c.Set("user_id",    cl.Custom["user_id"])
//	    c.Set("user_role",  cl.Custom["role"])
//	    c.Set("user_email", cl.Custom["email"])
//	})
//	r.Use(ginmw.JWT(svc, extractor, ginmw.WithWebSocketFallback()))
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
// # Custom claim guards
//
//	r.GET("/admin", ginmw.RequireCustomClaim("user_role", "admin", "superadmin"), handler)
//	r.Use(ginmw.RequireCustomClaimNot("user_role", "pending"))
//
// # Async DB-backed permission check
//
//	r.DELETE("/events/:id", ginmw.RequireAsyncPermission(
//	    "user_id",
//	    "user_role", "superadmin",
//	    func(ctx context.Context, subject, resource, action string) bool {
//	        return roleRepo.HasPermission(ctx, subject, resource, action)
//	    },
//	    "events", "delete",
//	), handler)
//
// # Scope checking (OAuth 2.0 / OIDC scopes)
//
//	r.GET("/profile", ginmw.ScopeChecker("read:profile"), handler)
package ginmw

import (
	"context"
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

// ─── JWT options ──────────────────────────────────────────────────────────────

// JWTOption configures the JWT middleware.
type JWTOption func(*jwtConfig)

type jwtConfig struct {
	extractor         ClaimsExtractor
	webSocketFallback bool
}

// ClaimsExtractor is called after successful token verification. Use it to
// unpack fields from claims.Custom into named Gin context values so that
// downstream handlers and middleware can access them with c.Get("key").
//
// Example:
//
//	ginmw.WithClaimsExtractor(func(c *gin.Context, cl *jwt.Claims) {
//	    c.Set("user_id",    cl.Custom["user_id"])
//	    c.Set("user_role",  cl.Custom["role"])
//	    c.Set("user_email", cl.Custom["email"])
//	})
type ClaimsExtractor func(c *gin.Context, claims *jwtpkg.Claims)

// WithClaimsExtractor registers a function that maps *jwt.Claims fields into
// named Gin context keys immediately after the token is verified.
func WithClaimsExtractor(fn ClaimsExtractor) JWTOption {
	return func(cfg *jwtConfig) { cfg.extractor = fn }
}

// WithWebSocketFallback enables token extraction from the ?token= query
// parameter when the Authorization header is absent on a WebSocket upgrade
// request (Connection: Upgrade + Upgrade: websocket). Browser WebSocket
// clients cannot set the Authorization header, so they pass the token
// as a query parameter instead.
func WithWebSocketFallback() JWTOption {
	return func(cfg *jwtConfig) { cfg.webSocketFallback = true }
}

// ─── JWT middleware ────────────────────────────────────────────────────────────

// JWT returns a Gin middleware that:
//  1. Extracts the Bearer token from the Authorization header.
//  2. Falls back to the ?token= query parameter on WebSocket upgrades
//     when WithWebSocketFallback is set.
//  3. Validates the token via svc.Verify (supports JWKS, HMAC, RSA, ECDSA).
//  4. Stores the *jwt.Claims in the Gin context under "ginmw:claims".
//  5. Calls the ClaimsExtractor (if set) to populate additional context keys.
//
// Requests without a valid token are rejected with 401. To make auth optional,
// apply this middleware only to protected route groups.
func JWT(svc *jwtpkg.Service, opts ...JWTOption) gin.HandlerFunc {
	cfg := &jwtConfig{}
	for _, o := range opts {
		o(cfg)
	}

	return func(c *gin.Context) {
		token := extractBearer(c.GetHeader("Authorization"))

		if token == "" && cfg.webSocketFallback && isWebSocketUpgrade(c.Request) {
			token = c.Query("token")
		}

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

		if cfg.extractor != nil {
			cfg.extractor(c, claims)
		}

		c.Next()
	}
}

// ─── RBAC middleware ──────────────────────────────────────────────────────────

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

// ─── Custom claim guards ──────────────────────────────────────────────────────

// RequireCustomClaim returns a middleware that rejects requests (403) unless
// the Gin context value at contextKey matches one of the allowedValues.
//
// The value at contextKey must be a string; a missing or non-string value is
// treated as denied.
//
// Must run after ginmw.JWT with a WithClaimsExtractor that populates contextKey.
//
// Example — require admin or superadmin role:
//
//	r.GET("/admin",
//	    ginmw.JWT(svc, extractor),
//	    ginmw.RequireCustomClaim("user_role", "admin", "superadmin"),
//	    handler,
//	)
func RequireCustomClaim(contextKey string, allowedValues ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		v, exists := c.Get(contextKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "forbidden: missing claim",
			})
			return
		}
		s, ok := v.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "forbidden: claim is not a string",
			})
			return
		}
		for _, allowed := range allowedValues {
			if s == allowed {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "forbidden: insufficient privileges",
		})
	}
}

// RequireCustomClaimNot returns a middleware that rejects requests (403) when
// the Gin context value at contextKey equals blockedValue. Useful for blocking
// accounts in a particular state (e.g. "pending", "suspended").
//
// If the key is absent from the context, the request is allowed through.
//
// Must run after ginmw.JWT with a WithClaimsExtractor that populates contextKey.
//
// Example — block pending accounts site-wide:
//
//	router.Use(ginmw.RequireCustomClaimNot("user_role", "pending"))
func RequireCustomClaimNot(contextKey, blockedValue string) gin.HandlerFunc {
	return func(c *gin.Context) {
		v, exists := c.Get(contextKey)
		if !exists {
			c.Next()
			return
		}
		if s, ok := v.(string); ok && s == blockedValue {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "forbidden: account not permitted",
			})
			return
		}
		c.Next()
	}
}

// ─── Async permission check ───────────────────────────────────────────────────

// PermissionFunc is a caller-supplied async permission-check function.
// subject is the value stored in the Gin context under subjectKey (e.g. a
// user ID or role string). resource and action describe the operation being
// attempted.
type PermissionFunc func(ctx context.Context, subject, resource, action string) bool

// RequireAsyncPermission returns a middleware that calls fn to check whether
// the request subject has permission to perform action on resource.
//
// subjectKey is the Gin context key holding the subject string (e.g. "user_id").
//
// bypassKey / bypassValue: when the context value at bypassKey equals
// bypassValue the permission check is skipped entirely (e.g. superadmin
// bypass). Pass empty strings to disable the bypass.
//
// Must run after ginmw.JWT with a WithClaimsExtractor that populates subjectKey
// (and bypassKey, if used).
//
// Example:
//
//	r.DELETE("/events/:id",
//	    ginmw.RequireAsyncPermission(
//	        "user_id",
//	        "user_role", "superadmin",
//	        func(ctx context.Context, subject, resource, action string) bool {
//	            return roleRepo.HasPermission(ctx, subject, resource, action)
//	        },
//	        "events", "delete",
//	    ),
//	    handler,
//	)
func RequireAsyncPermission(
	subjectKey string,
	bypassKey, bypassValue string,
	fn PermissionFunc,
	resource, action string,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Bypass check — e.g. superadmin skips permission lookup.
		if bypassKey != "" && bypassValue != "" {
			if bv, ok := c.Get(bypassKey); ok {
				if bs, ok := bv.(string); ok && bs == bypassValue {
					c.Next()
					return
				}
			}
		}

		// Resolve subject.
		sv, exists := c.Get(subjectKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthenticated",
			})
			return
		}
		subject, ok := sv.(string)
		if !ok || subject == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthenticated",
			})
			return
		}

		if !fn(c.Request.Context(), subject, resource, action) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "forbidden: " + action + " on " + resource + " not allowed",
			})
			return
		}

		c.Next()
	}
}

// ─── Scope checking ───────────────────────────────────────────────────────────

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

// ─── Context accessors ────────────────────────────────────────────────────────

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

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
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
