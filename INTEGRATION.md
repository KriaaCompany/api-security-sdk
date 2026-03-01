# api-security-sdk — Integration Guide

> **For AI agents**: This guide is structured for programmatic consumption. Each package section follows a fixed layout: _Purpose → When to use → Imports → Minimal example → All options → Integration patterns_. Use the [Decision Tree](#decision-tree) to select packages, then copy the relevant code blocks. All examples use `github.com/KriaaCompany/api-security-sdk` as the module path.

---

## Table of Contents

1. [Installation](#installation)
2. [Decision Tree](#decision-tree)
3. [Package Reference](#package-reference)
   - [auth/jwt](#authjwt) — Token signing & verification
   - [auth/middleware](#authmiddleware) — HTTP authentication middleware
   - [rbac](#rbac) — Role-Based Access Control
   - [abac](#abac) — Attribute-Based Access Control
   - [otp](#otp) — TOTP Two-Factor Authentication
   - [apikey](#apikey) — API Key Management
   - [ratelimit](#ratelimit) — Rate Limiting
   - [cors](#cors) — Cross-Origin Resource Sharing
   - [audit](#audit) — Security Audit Logging
   - [reqsign](#reqsign) — HMAC Request Signing
   - [passwdpolicy](#passwdpolicy) — Password Policy Enforcement
   - [secureheaders](#secureheaders) — Security Response Headers
   - [crypto](#crypto) — Cryptographic Utilities
4. [Middleware Composition Patterns](#middleware-composition-patterns)
5. [Complete Application Template](#complete-application-template)
6. [Implementing Custom Stores](#implementing-custom-stores)
7. [Error Reference](#error-reference)
8. [Production Checklist](#production-checklist)

---

## Installation

```sh
go get github.com/KriaaCompany/api-security-sdk
```

Import only the sub-packages you need. There is no root package to import.

```go
// Example: only JWT + RBAC
import (
    jwtpkg "github.com/KriaaCompany/api-security-sdk/auth/jwt"
    authmw "github.com/KriaaCompany/api-security-sdk/auth/middleware"
    "github.com/KriaaCompany/api-security-sdk/rbac"
)
```

---

## Decision Tree

Use this to select the right packages for a given requirement.

```
NEED TO...

Authenticate users?
├── Via username+password → crypto (hash) + auth/jwt (issue token)
├── Via API key           → apikey
├── Via existing JWT      → auth/middleware.JWT(svc)
└── Via mTLS              → use stdlib crypto/tls (outside scope)

Authorise requests?
├── User has role X?                            → rbac
├── User owns resource / has attribute?         → abac
├── Simple role check in handler (no middleware)→ rbac.Enforcer.Can(...)
└── Both role and attribute rules?              → rbac + abac in chain

Add Two-Factor Auth?
└── TOTP (Authenticator apps)                  → otp

Protect endpoints from abuse?
└── Rate limiting                              → ratelimit

Validate password strength?
└── Before hashing on signup/password-change   → passwdpolicy

Sign/verify webhook payloads?
└── Outbound or inbound HMAC-signed requests   → reqsign

Browser-facing API (React/Vue/mobile app)?
├── Cross-origin requests                      → cors
└── Security response headers                  → secureheaders

Audit trail / compliance logging?
└── SOC2, GDPR, ISO27001 event log             → audit

Generate cryptographic material?
└── Passwords, tokens, RSA/ECDSA keys         → crypto
```

---

## Package Reference

---

### auth/jwt

**Purpose**: Issue, verify, refresh, and revoke JWT tokens. Supports HMAC (HS256/384/512), RSA (RS256/512), and ECDSA (ES256/384/512).

**When to use**: Whenever you need to authenticate users or services via Bearer tokens. This is the central auth package — most other packages depend on the claims it produces.

**Import**:
```go
import jwtpkg "github.com/KriaaCompany/api-security-sdk/auth/jwt"
```

**Minimal example**:
```go
// Create service (do this once at startup, store as a singleton).
svc := jwtpkg.New(
    jwtpkg.WithHMAC([]byte("at-least-32-byte-secret-here!!!!!")),
)

// Issue a token (e.g. on login).
token, err := svc.Sign(jwtpkg.Claims{
    Subject: "user-123",
    Custom:  map[string]any{"email": "alice@example.com", "roles": []string{"admin"}},
})

// Verify a token (done automatically by auth/middleware.JWT).
claims, err := svc.Verify(token)
// claims.Subject  → "user-123"
// claims.Custom   → map[string]any{...}
// claims.ExpiresAt, claims.IssuedAt → time.Time
```

**All configuration options**:
```go
svc := jwtpkg.New(
    // Choose ONE signing algorithm:
    jwtpkg.WithHMAC(secret),                  // HS256 — symmetric, simplest
    jwtpkg.WithHMAC384(secret),               // HS384
    jwtpkg.WithHMAC512(secret),               // HS512
    jwtpkg.WithRSA(privKey, pubKey),           // RS256 — asymmetric
    jwtpkg.WithRSA512(privKey, pubKey),        // RS512
    jwtpkg.WithECDSA(privKey, pubKey),         // ES256/384/512 auto from curve

    // Optional:
    jwtpkg.WithExpiry(15 * time.Minute),       // token TTL (default: 1h)
    jwtpkg.WithIssuer("my-service"),           // sets "iss" claim
    jwtpkg.WithBlacklist(blacklist),           // enables revocation
)
```

**Token revocation**:
```go
bl := jwtpkg.NewMemoryBlacklist()             // swap for Redis in production
svc := jwtpkg.New(jwtpkg.WithHMAC(secret), jwtpkg.WithBlacklist(bl))

svc.Revoke(token)                             // add to blacklist
svc.Refresh(token)                            // revokes old, issues new
```

**Errors**:
| Error | Meaning |
|---|---|
| `jwtpkg.ErrExpiredToken` | Token TTL has elapsed |
| `jwtpkg.ErrInvalidToken` | Malformed, bad signature, or not-yet-valid |
| `jwtpkg.ErrTokenRevoked` | Token is in the blacklist |
| `jwtpkg.ErrInvalidSigningMethod` | Token was signed with a different algorithm |
| `jwtpkg.ErrMissingAlgorithm` | No algorithm option was passed to `New` |

**Key generation** (use `crypto` package):
```go
import "github.com/KriaaCompany/api-security-sdk/crypto"

// ECDSA (recommended — smaller keys than RSA)
priv, pub, _ := crypto.GenerateECDSAKeyPair(elliptic.P256())
svc := jwtpkg.New(jwtpkg.WithECDSA(priv, pub))

// RSA
priv, pub, _ := crypto.GenerateRSAKeyPair(2048)
svc := jwtpkg.New(jwtpkg.WithRSA(priv, pub))
```

---

### auth/middleware

**Purpose**: HTTP middleware that extracts and validates Bearer tokens, and stores the resulting claims in the request context for downstream handlers.

**When to use**: Apply to every route that requires authentication. Always use this before `rbac` or `abac` middleware.

**Import**:
```go
import authmw "github.com/KriaaCompany/api-security-sdk/auth/middleware"
```

**Minimal example**:
```go
// Require a valid token on every request to this route.
mux.Handle("/api/", authmw.JWT(svc)(apiHandler))

// Inside a handler — read the authenticated user.
func apiHandler(w http.ResponseWriter, r *http.Request) {
    subject := authmw.SubjectFrom(r.Context())       // "user-123"
    claims  := authmw.ClaimsFrom(r.Context())        // *jwtpkg.Claims
    email   := authmw.CustomClaimFrom(r.Context(), "email") // any
}
```

**All functions**:
```go
// Middleware constructors.
authmw.JWT(svc)                     // reject requests with no/invalid token → 401
authmw.Optional(svc)                // pass through even without a token
authmw.RequireAuth(onError?)        // 401 if no claims in context; pair with Optional

// Context accessors (safe to call when no claims are present — return zero values).
authmw.ClaimsFrom(ctx)              // *jwtpkg.Claims | nil
authmw.SubjectFrom(ctx)             // string | ""
authmw.CustomClaimFrom(ctx, "key") // any | nil
```

**Custom error handler** (e.g. to return XML or redirect):
```go
authmw.JWT(svc,
    authmw.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
        http.Redirect(w, r, "/login", http.StatusFound)
    }),
)
```

**Optional auth pattern** (endpoint serves both authenticated and anonymous users):
```go
mux.Handle("/feed",
    authmw.Optional(svc)(            // populate claims if token present
        authmw.RequireAuth()(        // if you need to force auth after Optional
            feedHandler,
        ),
    ),
)
```

---

### rbac

**Purpose**: Role-Based Access Control with transitive role inheritance and wildcard permissions.

**When to use**: When access rules depend on *who the user is* (their role), not on specific resource attributes. Simpler and faster than ABAC.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/rbac"
```

**Minimal example**:
```go
store := rbac.NewMemoryStore()

store.AddRole(rbac.Role{
    Name:        "viewer",
    Permissions: []rbac.Permission{{Resource: "*", Action: "read"}},
})
store.AddRole(rbac.Role{
    Name:    "editor",
    Parents: []string{"viewer"}, // inherits all viewer permissions
    Permissions: []rbac.Permission{
        {Resource: "posts", Action: "create"},
        {Resource: "posts", Action: "update"},
    },
})

store.AssignRole("user-123", "editor")

enforcer := rbac.New(store)

enforcer.Can("user-123", "read", "posts")   // true (inherited)
enforcer.Can("user-123", "create", "posts") // true (direct)
enforcer.Can("user-123", "delete", "users") // false
```

**Permission wildcards**:
```go
{Resource: "*", Action: "*"}      // full access (admin)
{Resource: "*", Action: "read"}   // read anything
{Resource: "posts", Action: "*"}  // any action on posts
```

**HTTP middleware**:
```go
// Always chain AFTER authmw.JWT — RBAC reads the subject from context.
mux.Handle("/posts",
    authmw.JWT(svc)(
        rbac.Require(enforcer, "read", "posts")(
            handler,
        ),
    ),
)

// Require the subject to have one of these roles directly assigned.
mux.Handle("/admin",
    authmw.JWT(svc)(
        rbac.RequireRole(enforcer, "admin", "superadmin")(
            adminHandler,
        ),
    ),
)
```

**Store interface** (for database-backed stores):
```go
type rbac.Store interface {
    GetRole(name string) (Role, error)
    GetSubjectRoles(subject string) ([]string, error)
    AssignRole(subject, role string) error
    UnassignRole(subject, role string) error
    AddRole(role Role) error
    RemoveRole(name string) error
}
```

---

### abac

**Purpose**: Attribute-Based Access Control — policies evaluated against subject, resource, action, and environment attributes. Deny-by-default.

**When to use**: When access rules depend on *the specific resource* being accessed (e.g. "users can only edit their own posts") or dynamic environmental conditions. More expressive than RBAC, slightly more complex to configure.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/abac"
```

**Minimal example**:
```go
store := abac.NewMemoryStore()

// Policy: owners may read/update/delete their own resources.
store.AddPolicy(abac.Policy{
    ID:       "owner-access",
    Effect:   abac.Allow,
    Priority: 50,
    Condition: abac.And(
        abac.OwnerIsSubject(),
        abac.ActionIs("read", "update", "delete"),
    ),
})

ev := abac.New(store) // deny-by-default

decision := ev.Evaluate(abac.Request{
    Subject:  abac.Attributes{"id": "user-123"},
    Resource: abac.Attributes{"owner": "user-123", "type": "post"},
    Action:   "update",
})
// decision.Allowed → true
// decision.MatchedPolicy → "owner-access"
```

**All built-in conditions**:
```go
abac.ActionIs("read", "update")              // action matches any of these values
abac.SubjectAttrEquals("department", "eng")  // subject["department"] == "eng"
abac.ResourceAttrEquals("status", "draft")   // resource["status"] == "draft"
abac.EnvAttrEquals("method", "GET")          // environment["method"] == "GET"
abac.OwnerIsSubject()                        // resource["owner"] == subject["id"]
abac.SubjectHasRole("admin")                 // subject["roles"] contains "admin"

// Combinators.
abac.And(cond1, cond2, cond3)
abac.Or(cond1, cond2)
abac.Not(cond)

// Custom condition (plain function).
abac.Condition(func(req abac.Request) bool {
    return req.Environment["ip"] == "10.0.0.0/8" // your logic here
})
```

**Policy priority**: Higher number = evaluated first. First matching policy wins.
```go
abac.Policy{ID: "admin-all",   Priority: 100, Effect: abac.Allow, Condition: abac.SubjectHasRole("admin")}
abac.Policy{ID: "deny-root",   Priority: 90,  Effect: abac.Deny,  Condition: abac.ResourceAttrEquals("owner", "root")}
abac.Policy{ID: "owner-write", Priority: 50,  Effect: abac.Allow, Condition: abac.OwnerIsSubject()}
abac.Policy{ID: "public-read", Priority: 10,  Effect: abac.Allow, Condition: abac.And(abac.ResourceAttrEquals("public", true), abac.ActionIs("read"))}
```

**HTTP middleware**:
```go
mux.Handle("/posts/",
    authmw.JWT(svc)(
        abac.Require(
            ev,
            "update",                           // the action
            func(r *http.Request) abac.Attributes {
                // Load the resource from DB using the request (e.g. path param).
                id := strings.TrimPrefix(r.URL.Path, "/posts/")
                post := db.GetPost(id)
                return abac.Attributes{
                    "owner": post.AuthorID,
                    "status": post.Status,
                }
            },
            abac.SubjectFromClaims,             // maps JWT claims → subject attrs
        )(handler),
    ),
)
```

**`abac.SubjectFromClaims`** automatically sets:
- `subject["id"]` ← `claims.Subject`
- `subject["*"]` ← all `claims.Custom` fields (e.g. `subject["roles"]`, `subject["email"]`)

**Store interface**:
```go
type abac.PolicyStore interface {
    AddPolicy(policy Policy) error
    RemovePolicy(id string) error
    Policies() ([]Policy, error)
}
```

---

### otp

**Purpose**: RFC 6238 Time-based One-Time Password (TOTP) for two-factor authentication. Compatible with Google Authenticator, Authy, 1Password, and all TOTP apps. Uses only the Go standard library.

**When to use**: When you want to add a second factor to username+password login.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/otp"
```

**Full 2FA flow**:
```go
// ── STEP 1: Account setup (one time per user) ────────────────────────────────

secret, err := otp.NewSecret()       // e.g. "JBSWY3DPEHPK3PXP"
// Store secret encrypted in your user record.
db.SaveTOTPSecret(userID, encrypt(secret))

// Generate a QR code URI for the user to scan with their authenticator app.
uri := otp.ProvisioningURI("alice@example.com", "MyApp", secret)
// Render uri as a QR code. Any QR library works, e.g. github.com/skip2/go-qrcode.

// ── STEP 2: Every login ──────────────────────────────────────────────────────

secret := decrypt(db.GetTOTPSecret(userID))
userCode := r.FormValue("totp_code")          // 6-digit code from the user's app

ok, err := otp.Verify(secret, userCode)
if err != nil || !ok {
    // Reject login — code is wrong or expired.
}
// Issue JWT or session on success.

// ── STEP 3: Backup codes (generate once, show once, store hashed) ────────────

codes, err := otp.GenerateBackupCodes(10)
// codes → ["A3K9M-X7P2Q", "B4L0N-Y8Q3R", ...]
// Hash each code with crypto.HashPassword before storing.
// On use: crypto.VerifyPassword(inputCode, storedHash), then mark as used.
```

**Custom verification options**:
```go
ok, err := otp.VerifyWithOptions(secret, code, otp.VerifyOptions{
    Digits: 8,    // 8-digit codes (default: 6)
    Period: 60,   // 60-second window (default: 30)
    Skew:   2,    // ±2 time steps (default: 1, i.e. ±30 seconds)
})
```

---

### apikey

**Purpose**: API key generation, storage (hashed), expiry, revocation, and HTTP middleware. Keys are prefixed base62 strings (e.g. `sk_live_A3Bx…`). Only the SHA-256 hash is stored.

**When to use**: Service-to-service authentication, CI/CD integrations, developer API keys. Use instead of (or alongside) JWT when stateless tokens are not suitable.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/apikey"
```

**Full lifecycle**:
```go
store := apikey.NewMemoryStore()    // replace with DB store in production
svc   := apikey.NewService(store)

// ── Issue ────────────────────────────────────────────────────────────────────
issued, err := svc.Issue(apikey.IssueOptions{
    Prefix:    "sk_live",               // key = "sk_live_<40 random base62 chars>"
    Name:      "github-actions",        // human label
    Subject:   "user-123",             // link to a user/service
    ExpiresIn: 90 * 24 * time.Hour,    // optional TTL (0 = never expires)
    Metadata:  map[string]any{"scopes": []string{"read", "write"}},
})
fmt.Println(issued.Plaintext)           // show to user ONCE — never stored internally
fmt.Println(issued.Key.ID)             // short ID for management

// ── Verify (called by middleware automatically) ───────────────────────────────
key, err := svc.Verify(rawKeyFromRequest)
// err: apikey.ErrInvalidKey | ErrRevokedKey | ErrExpiredKey

// ── Revoke ───────────────────────────────────────────────────────────────────
svc.Revoke(key.ID)
```

**HTTP middleware**:
```go
// Reads key from X-API-Key header OR Authorization: Bearer <key>.
mux.Handle("/api/", apikey.Middleware(svc)(handler))

// Inside handler.
func handler(w http.ResponseWriter, r *http.Request) {
    k := apikey.KeyFrom(r.Context())        // *apikey.Key
    s := apikey.SubjectFrom(r.Context())    // string (key.Subject)
    _ = k.Metadata["scopes"]
}
```

**Store interface**:
```go
type apikey.Store interface {
    Save(k *Key) error
    GetByHash(hash string) (*Key, error)
    GetByID(id string) (*Key, error)
    Revoke(id string) error
    ListBySubject(subject string) ([]*Key, error)
}
```

---

### ratelimit

**Purpose**: Sliding-window request rate limiting with standard `X-RateLimit-*` headers. Responds with `429 Too Many Requests` on breach.

**When to use**: Apply to all public-facing endpoints, login endpoints (stricter), and expensive operations.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/ratelimit"
```

**Minimal example**:
```go
store   := ratelimit.NewMemoryStore()   // replace with Redis store in production
limiter := ratelimit.New(store, ratelimit.Config{
    Limit:  100,
    Window: time.Minute,
})
mux.Handle("/api/", limiter(handler))
```

**All configuration options**:
```go
ratelimit.Config{
    Limit:  100,                         // max requests per Window
    Window: time.Minute,                 // sliding window duration
    KeyFn:  ratelimit.ByIP,              // how to identify a client (see below)
    OnLimited: func(w http.ResponseWriter, r *http.Request, reset time.Time) {
        // custom 429 response
    },
}
```

**Key functions** (choose how to identify clients):
```go
ratelimit.ByIP                              // remote IP (default)
ratelimit.ByRoute                           // IP + URL path
ratelimit.BySubject(authmw.SubjectFrom)     // JWT subject (falls back to IP)

// Custom key (e.g. API key subject):
KeyFn: func(r *http.Request) string {
    if k := apikey.KeyFrom(r.Context()); k != nil {
        return "apikey:" + k.Subject
    }
    return r.RemoteAddr
}
```

**Response headers set on every response**:
```
X-RateLimit-Limit:     100
X-RateLimit-Remaining: 73
X-RateLimit-Reset:     1735689600   (unix timestamp)
Retry-After: 60                     (only on 429)
```

**Multiple limits** (different limits per route):
```go
strictLimiter := ratelimit.New(store, ratelimit.Config{Limit: 5,   Window: time.Minute})  // login
normalLimiter := ratelimit.New(store, ratelimit.Config{Limit: 100, Window: time.Minute})  // API

mux.Handle("/login", strictLimiter(loginHandler))
mux.Handle("/api/",  normalLimiter(apiHandler))
```

**Store interface**:
```go
type ratelimit.Store interface {
    Inc(key string, window time.Duration) (count int64, err error)
    Reset(key string) error
}
```

---

### cors

**Purpose**: Cross-Origin Resource Sharing middleware. Controls which browser origins may call your API.

**When to use**: Any API consumed by a browser-based frontend (React, Vue, Angular, etc.).

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/cors"
```

**Production setup**:
```go
mux.Handle("/", cors.New(cors.Config{
    AllowedOrigins:   []string{"https://app.example.com"},
    AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
    AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-Id"},
    ExposedHeaders:   []string{"X-RateLimit-Remaining", "X-RateLimit-Reset"},
    AllowCredentials: true,   // required for cookies/Authorization header
    MaxAge:           12 * time.Hour,
})(handler))
```

**Development** (all origins, never production):
```go
mux.Handle("/", cors.AllowAll()(handler))
```

**Important rules**:
- `AllowCredentials: true` requires an explicit origin in `AllowedOrigins`, never `"*"`.
- Apply CORS as the *outermost* middleware so preflight (`OPTIONS`) requests are handled before auth.
- `Vary: Origin` is always set automatically — no extra configuration needed.

**Ordering** (CORS must wrap everything else):
```go
mux.Handle("/api/",
    cors.New(cfg)(                      // 1. CORS (outermost)
        secureheaders.Strict()(         // 2. Security headers
            ratelimit.New(...)(         // 3. Rate limiting
                authmw.JWT(svc)(        // 4. Authentication
                    handler,
                ),
            ),
        ),
    ),
)
```

---

### audit

**Purpose**: Structured security event logging for authentication and authorisation actions. Compatible with Loki, Datadog, CloudWatch, and Splunk via newline-delimited JSON.

**When to use**: Any application with compliance requirements (SOC 2, ISO 27001, GDPR). Also useful for incident investigation.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/audit"
```

**Setup**:
```go
logger := audit.NewJSONLogger(os.Stdout)            // or any io.Writer

// Inject into every request via middleware.
mux.Handle("/", audit.Middleware(logger)(handler))

// Auto-log every request (status ≥ 400 → EventAccessDenied):
mux.Handle("/", audit.Middleware(logger, true)(handler))
```

**Logging events inside handlers**:
```go
// Fluent builder — recommended.
audit.Eventf(audit.EventLogin, userID, audit.ResultAllow).
    WithIP(r.RemoteAddr).
    WithMeta("method", "password").
    Log(r.Context())

// Direct struct — for full control.
audit.Log(r.Context(), audit.Event{
    Type:      audit.EventAccessDenied,
    Subject:   userID,
    Resource:  "/admin/users",
    Action:    "DELETE",
    Result:    audit.ResultDeny,
    IP:        r.RemoteAddr,
    UserAgent: r.UserAgent(),
    RequestID: r.Header.Get("X-Request-Id"),
})
```

**All event types**:
```go
// Authentication
audit.EventLogin, audit.EventLoginFailed, audit.EventLogout
audit.EventMFASuccess, audit.EventMFAFailed

// Tokens
audit.EventTokenIssued, audit.EventTokenVerified
audit.EventTokenRefreshed, audit.EventTokenRevoked
audit.EventTokenExpired, audit.EventTokenInvalid

// API Keys
audit.EventAPIKeyIssued, audit.EventAPIKeyUsed
audit.EventAPIKeyRevoked, audit.EventAPIKeyInvalid

// Authorisation
audit.EventAccessGranted, audit.EventAccessDenied

// Rate limiting
audit.EventRateLimited

// Account
audit.EventPasswordChanged, audit.EventPasswordReset
audit.EventAccountLocked, audit.EventAccountUnlocked
```

**Multiple sinks** (e.g. stdout + remote):
```go
logger := audit.NewMultiLogger(
    audit.NewJSONLogger(os.Stdout),
    myRemoteLogger,          // any type that implements audit.Logger
)
```

**Custom logger implementation**:
```go
type audit.Logger interface {
    Log(ctx context.Context, event audit.Event) error
}
```

---

### reqsign

**Purpose**: HMAC-SHA256 request signing and verification with replay-attack protection. Implements the same scheme used by Stripe, GitHub, and Twilio webhooks.

**When to use**:
- Verifying inbound webhooks from third-party services.
- Authenticating service-to-service HTTP calls without JWT.
- Signing outbound webhook deliveries to your customers.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/reqsign"
```

**Signed payload format**: `"<unix-timestamp-seconds>\n<request-body>"` — the timestamp binds the signature to a point in time for replay protection.

**Outbound — signing requests you send**:
```go
secret := []byte("shared-secret-at-least-32-bytes!!")
client := &http.Client{
    Transport: reqsign.NewSigningTransport(secret, nil),
}
// Every request is automatically signed:
// X-Timestamp: 1735689600
// X-Signature: a3b4c5d6...  (hex HMAC-SHA256)
client.Post(webhookURL, "application/json", body)
```

**Inbound — verifying webhooks you receive**:
```go
mux.Handle("/webhooks/stripe",
    reqsign.Middleware(stripeSecret)(stripeHandler),
)
// Invalid signature or timestamp outside ±5 min window → 401.
```

**Custom header names** (e.g. GitHub-compatible):
```go
reqsign.Middleware(secret, reqsign.VerifyOptions{
    Header:          "X-Hub-Signature-256",
    TimestampHeader: "X-GitHub-Delivery",
    ReplayWindow:    10 * time.Minute,
})(handler)
```

**Manual sign/verify** (for non-HTTP use cases):
```go
sig := reqsign.Sign(secret, payloadBytes, time.Now())
ok  := reqsign.Verify(secret, payloadBytes, timestamp, sig)
```

---

### passwdpolicy

**Purpose**: Validate password strength before hashing. Returns structured violations for API error responses. Complements `crypto.HashPassword`.

**When to use**: On user registration and password change endpoints, before calling `crypto.HashPassword`.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/passwdpolicy"
```

**Usage pattern**:
```go
// Registration handler.
func handleSignup(w http.ResponseWriter, r *http.Request) {
    password := r.FormValue("password")

    policy := passwdpolicy.OWASP()                     // or passwdpolicy.Strict()
    violations := policy.Validate(password)
    if len(violations) > 0 {
        // Return violations as JSON errors.
        for _, v := range violations {
            // v.Rule    → "min_length"
            // v.Message → "must be at least 8 characters long"
        }
        http.Error(w, "password does not meet requirements", http.StatusBadRequest)
        return
    }

    hash, err := crypto.HashPassword(password)         // safe to hash now
    db.SaveUser(email, hash)
}
```

**Preset policies**:
```go
passwdpolicy.OWASP()    // min 8 chars, entropy ≥ 28 bits, block common passwords
passwdpolicy.Strict()   // min 12 chars, upper+lower+digit+special, entropy ≥ 50 bits
```

**Custom policy**:
```go
policy := passwdpolicy.Policy{
    MinLength:      16,
    MaxLength:      128,           // NIST recommends allowing long passwords
    RequireUpper:   true,
    RequireLower:   true,
    RequireDigit:   true,
    RequireSpecial: true,
    MinEntropy:     60,            // bits; 28=weak, 36=ok, 50=strong, 60=very strong
    DisallowCommon: true,          // built-in top-100 breach list
    Blocklist:      []string{"MyCompany", "MyProduct", "CompanyName123"},
}
```

**Strength meter** (for UI feedback, independent of policy):
```go
strength := passwdpolicy.EstimateStrength(password)
// strength.String() → "very weak" | "weak" | "fair" | "strong" | "very strong"
```

---

### secureheaders

**Purpose**: Sets security-relevant HTTP response headers in one call. Apply once at the outermost middleware layer.

**When to use**: Every HTTP service — browser-facing or not. Most headers are harmless to APIs and protect against browser-based attacks.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/secureheaders"
```

**Strict preset** (recommended — apply to everything):
```go
mux.Handle("/", secureheaders.Strict()(handler))
```

Headers set by `Strict()`:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
(Server and X-Powered-By headers removed)
```

**Custom configuration**:
```go
secureheaders.New(secureheaders.Config{
    HSTS: secureheaders.HSTSConfig{
        MaxAge:            365 * 24 * time.Hour,
        IncludeSubDomains: true,
        Preload:           false,             // only true after hstspreload.org submission
    },
    ContentTypeOpts:    true,
    FrameOptions:       "SAMEORIGIN",         // or "DENY"
    XSSProtection:      true,
    CSP:                "default-src 'self'; script-src 'self' 'nonce-{NONCE}'",
    ReferrerPolicy:     "strict-origin-when-cross-origin",
    PermissionsPolicy:  "geolocation=(), microphone=()",
    COEP:               "require-corp",
    COOP:               "same-origin",
    CORP:               "same-origin",
    RemoveServerHeader: true,
    RemovePoweredBy:    true,
})
```

---

### crypto

**Purpose**: Cryptographic utilities — Argon2id password hashing, secure random token generation, and RSA/ECDSA key management.

**When to use**: Any time you need to hash a password, generate a token, or create asymmetric keys for JWT.

**Import**:
```go
import "github.com/KriaaCompany/api-security-sdk/crypto"
```

**Password hashing (Argon2id)**:
```go
// Hash on registration/password-change (run passwdpolicy.Validate first).
hash, err := crypto.HashPassword(password)
// hash → "$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>"
// Store hash in database. Never store the plaintext password.

// Verify on login.
ok, err := crypto.VerifyPassword(submittedPassword, storedHash)

// Custom parameters (tune for your hardware).
hash, err := crypto.HashPasswordWithConfig(password, crypto.PasswordConfig{
    Memory:      128 * 1024, // 128 MiB
    Iterations:  4,
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
})
```

**Secure random tokens**:
```go
// 32 bytes = 256 bits of entropy. Use for: session IDs, CSRF tokens, API keys, reset tokens.
token, err := crypto.GenerateToken(32)
// token → "4Xy9mQz..." (base64url, no padding)

// Panic variant for init code/tests only.
token := crypto.MustGenerateToken(32)
```

**RSA key generation**:
```go
priv, pub, err := crypto.GenerateRSAKeyPair(2048)      // minimum 2048; prefer 4096

privPEM, err := crypto.RSAPrivateKeyToPEM(priv)
pubPEM,  err := crypto.RSAPublicKeyToPEM(pub)

// Load back from PEM (e.g. from file or environment variable).
priv, err := crypto.ParseRSAPrivateKeyPEM(privPEM)
pub,  err := crypto.ParseRSAPublicKeyPEM(pubPEM)
```

**ECDSA key generation** (smaller, faster than RSA):
```go
priv, pub, err := crypto.GenerateECDSAKeyPair(elliptic.P256())  // → ES256
priv, pub, err := crypto.GenerateECDSAKeyPair(elliptic.P384())  // → ES384
priv, pub, err := crypto.GenerateECDSAKeyPair(elliptic.P521())  // → ES512

privPEM, err := crypto.ECDSAPrivateKeyToPEM(priv)
pubPEM,  err := crypto.ECDSAPublicKeyToPEM(pub)
priv, err    := crypto.ParseECDSAPrivateKeyPEM(privPEM)
```

---

## Middleware Composition Patterns

All middleware follows the standard `func(http.Handler) http.Handler` signature. Chain them by nesting: the outermost function runs first.

### Pattern 1 — Public read API with rate limiting

```go
mux.Handle("/api/v1/",
    cors.New(corsConfig)(
        secureheaders.Strict()(
            ratelimit.New(store, ratelimit.Config{Limit: 60, Window: time.Minute})(
                handler,
            ),
        ),
    ),
)
```

### Pattern 2 — Authenticated REST API with RBAC

```go
mux.Handle("/api/v1/posts",
    cors.New(corsConfig)(
        secureheaders.Strict()(
            ratelimit.New(store, ratelimit.Config{Limit: 100, Window: time.Minute})(
                authmw.JWT(jwtSvc)(
                    rbac.Require(enforcer, "read", "posts")(
                        handler,
                    ),
                ),
            ),
        ),
    ),
)
```

### Pattern 3 — Resource-owner endpoint with ABAC

```go
mux.Handle("/api/v1/posts/",
    cors.New(corsConfig)(
        secureheaders.Strict()(
            authmw.JWT(jwtSvc)(
                abac.Require(
                    ev,
                    r.Method,           // action = HTTP method
                    loadPostAttrs,       // func(*http.Request) abac.Attributes
                    abac.SubjectFromClaims,
                )(handler),
            ),
        ),
    ),
)
```

### Pattern 4 — API key authenticated service endpoint

```go
mux.Handle("/api/internal/",
    secureheaders.Strict()(
        ratelimit.New(store, ratelimit.Config{Limit: 1000, Window: time.Minute})(
            apikey.Middleware(apiSvc)(
                handler,
            ),
        ),
    ),
)
```

### Pattern 5 — Webhook receiver (inbound request signing)

```go
mux.Handle("/webhooks/",
    reqsign.Middleware(webhookSecret)(
        audit.Middleware(logger)(
            webhookHandler,
        ),
    ),
)
```

### Pattern 6 — Full security stack (login endpoint)

```go
mux.Handle("/auth/login",
    cors.New(corsConfig)(
        secureheaders.Strict()(
            ratelimit.New(store, ratelimit.Config{Limit: 5, Window: time.Minute})(
                audit.Middleware(auditLogger, true)(
                    loginHandler,
                ),
            ),
        ),
    ),
)
```

---

## Complete Application Template

Copy this file as a starting point. Replace every `// TODO` comment.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "time"

    "github.com/KriaaCompany/api-security-sdk/abac"
    "github.com/KriaaCompany/api-security-sdk/apikey"
    "github.com/KriaaCompany/api-security-sdk/audit"
    jwtpkg "github.com/KriaaCompany/api-security-sdk/auth/jwt"
    authmw "github.com/KriaaCompany/api-security-sdk/auth/middleware"
    "github.com/KriaaCompany/api-security-sdk/cors"
    "github.com/KriaaCompany/api-security-sdk/crypto"
    "github.com/KriaaCompany/api-security-sdk/otp"
    "github.com/KriaaCompany/api-security-sdk/passwdpolicy"
    "github.com/KriaaCompany/api-security-sdk/rbac"
    "github.com/KriaaCompany/api-security-sdk/ratelimit"
    "github.com/KriaaCompany/api-security-sdk/reqsign"
    "github.com/KriaaCompany/api-security-sdk/secureheaders"
)

func main() {
    // ── Crypto / keys ─────────────────────────────────────────────────────────
    // TODO: Load keys from environment or secret manager, not hardcoded.
    jwtSecret := []byte(os.Getenv("JWT_SECRET")) // min 32 bytes

    // ── JWT ───────────────────────────────────────────────────────────────────
    blacklist := jwtpkg.NewMemoryBlacklist() // TODO: use Redis blacklist
    jwtSvc := jwtpkg.New(
        jwtpkg.WithHMAC(jwtSecret),
        jwtpkg.WithExpiry(15*time.Minute),
        jwtpkg.WithIssuer("my-api"),
        jwtpkg.WithBlacklist(blacklist),
    )

    // ── RBAC ──────────────────────────────────────────────────────────────────
    rbacStore := rbac.NewMemoryStore() // TODO: use DB store
    rbacStore.AddRole(rbac.Role{Name: "admin", Permissions: []rbac.Permission{{Resource: "*", Action: "*"}}})
    rbacStore.AddRole(rbac.Role{Name: "user",  Permissions: []rbac.Permission{{Resource: "*", Action: "read"}}})
    enforcer := rbac.New(rbacStore)

    // ── ABAC ──────────────────────────────────────────────────────────────────
    abacStore := abac.NewMemoryStore() // TODO: use DB store
    abacStore.AddPolicy(abac.Policy{
        ID: "owner-write", Effect: abac.Allow, Priority: 50,
        Condition: abac.And(abac.OwnerIsSubject(), abac.ActionIs("update", "delete")),
    })
    ev := abac.New(abacStore)

    // ── API Keys ──────────────────────────────────────────────────────────────
    apikeyStore := apikey.NewMemoryStore() // TODO: use DB store
    apiSvc := apikey.NewService(apikeyStore)

    // ── Rate limiting ─────────────────────────────────────────────────────────
    rlStore := ratelimit.NewMemoryStore() // TODO: use Redis store
    apiLimiter   := ratelimit.New(rlStore, ratelimit.Config{Limit: 100, Window: time.Minute})
    loginLimiter := ratelimit.New(rlStore, ratelimit.Config{Limit: 5,   Window: time.Minute})

    // ── CORS ──────────────────────────────────────────────────────────────────
    corsMiddleware := cors.New(cors.Config{
        AllowedOrigins:   []string{"https://app.example.com"}, // TODO: your frontend origin
        AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
        AllowedHeaders:   []string{"Authorization", "Content-Type"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    })

    // ── Audit logging ─────────────────────────────────────────────────────────
    auditLogger := audit.NewJSONLogger(os.Stdout)

    // ── Webhook signing ───────────────────────────────────────────────────────
    webhookSecret := []byte(os.Getenv("WEBHOOK_SECRET")) // TODO: load from env

    // ── Password policy ───────────────────────────────────────────────────────
    pwPolicy := passwdpolicy.OWASP()

    // ── Routes ────────────────────────────────────────────────────────────────
    mux := http.NewServeMux()

    // ── Auth endpoints ────────────────────────────────────────────────────────

    // POST /auth/register
    mux.Handle("/auth/register",
        corsMiddleware(secureheaders.Strict()(loginLimiter(
            http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                password := r.FormValue("password")
                if violations := pwPolicy.Validate(password); len(violations) > 0 {
                    http.Error(w, violations[0].Message, http.StatusBadRequest)
                    return
                }
                hash, _ := crypto.HashPassword(password)
                _ = hash // TODO: save user with hash
                w.WriteHeader(http.StatusCreated)
            }),
        ))))

    // POST /auth/login
    mux.Handle("/auth/login",
        corsMiddleware(secureheaders.Strict()(loginLimiter(audit.Middleware(auditLogger,
            http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                userID := r.FormValue("email") // TODO: look up user, verify password
                token, _ := jwtSvc.Sign(jwtpkg.Claims{
                    Subject: userID,
                    Custom:  map[string]any{"roles": []string{"user"}},
                })
                audit.Eventf(audit.EventLogin, userID, audit.ResultAllow).
                    WithIP(r.RemoteAddr).Log(r.Context())
                w.Header().Set("Content-Type", "application/json")
                w.Write([]byte(`{"token":"` + token + `"}`))
            }),
        )))))

    // POST /auth/logout
    mux.Handle("/auth/logout",
        corsMiddleware(secureheaders.Strict()(authmw.JWT(jwtSvc)(
            http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                token := r.Header.Get("Authorization")[len("Bearer "):]
                jwtSvc.Revoke(token)
                audit.Eventf(audit.EventLogout, authmw.SubjectFrom(r.Context()), audit.ResultAllow).
                    Log(r.Context())
                w.WriteHeader(http.StatusNoContent)
            }),
        ))))

    // ── OTP / 2FA ─────────────────────────────────────────────────────────────

    // POST /auth/totp/setup
    mux.Handle("/auth/totp/setup",
        corsMiddleware(secureheaders.Strict()(authmw.JWT(jwtSvc)(
            http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                secret, _ := otp.NewSecret()
                uri := otp.ProvisioningURI(authmw.SubjectFrom(r.Context()), "MyApp", secret)
                _ = secret // TODO: encrypt and save to user record
                _ = uri    // TODO: return as JSON or render as QR code
            }),
        ))))

    // ── RBAC-protected resource ────────────────────────────────────────────────

    // GET /posts — requires authenticated user with read permission
    mux.Handle("/posts",
        corsMiddleware(secureheaders.Strict()(apiLimiter(
            authmw.JWT(jwtSvc)(rbac.Require(enforcer, "read", "posts")(
                http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                    subject := authmw.SubjectFrom(r.Context())
                    _ = subject // TODO: query posts for subject
                    w.Write([]byte(`{"posts":[]}`))
                }),
            )),
        ))))

    // ── ABAC-protected resource ────────────────────────────────────────────────

    // PUT /posts/{id} — only the owner may update
    mux.Handle("/posts/",
        corsMiddleware(secureheaders.Strict()(apiLimiter(
            authmw.JWT(jwtSvc)(abac.Require(ev, "update",
                func(r *http.Request) abac.Attributes {
                    id := r.URL.Path[len("/posts/"):]
                    _ = id // TODO: load post from DB
                    return abac.Attributes{"owner": "user-from-db"}
                },
                abac.SubjectFromClaims,
            )(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte(`{"updated":true}`))
            }))),
        ))))

    // ── API key protected internal endpoint ───────────────────────────────────

    // GET /internal/metrics — service-to-service only
    mux.Handle("/internal/",
        secureheaders.Strict()(apiLimiter(apikey.Middleware(apiSvc)(
            http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                k := apikey.KeyFrom(r.Context())
                _ = k // TODO: authorise by key metadata
                w.Write([]byte(`{"status":"ok"}`))
            }),
        ))))

    // ── Webhook receiver ──────────────────────────────────────────────────────

    // POST /webhooks/events — verify HMAC signature
    mux.Handle("/webhooks/",
        reqsign.Middleware(webhookSecret)(audit.Middleware(auditLogger)(
            http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                // Body has been verified and is readable.
                w.WriteHeader(http.StatusOK)
            }),
        )))

    // ── Issue an API key (admin only) ─────────────────────────────────────────
    mux.Handle("/api/keys",
        corsMiddleware(secureheaders.Strict()(authmw.JWT(jwtSvc)(
            rbac.Require(enforcer, "create", "apikeys")(
                http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                    issued, _ := apiSvc.Issue(apikey.IssueOptions{
                        Prefix:  "sk_live",
                        Subject: authmw.SubjectFrom(r.Context()),
                        Name:    r.FormValue("name"),
                    })
                    audit.Eventf(audit.EventAPIKeyIssued, issued.Key.Subject, audit.ResultAllow).
                        WithMeta("key_id", issued.Key.ID).Log(r.Context())
                    w.Write([]byte(`{"key":"` + issued.Plaintext + `"}`))
                }),
            ),
        ))))

    _ = context.Background() // suppress unused import
    log.Println("Listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

---

## Implementing Custom Stores

Every stateful component accepts a Store interface. Implement these to use PostgreSQL, Redis, or any other backend without changing application code.

### RBAC Store (PostgreSQL example skeleton)

```go
type PostgresRBACStore struct{ db *sql.DB }

func (s *PostgresRBACStore) GetRole(name string) (rbac.Role, error) {
    // SELECT name, parents, permissions FROM roles WHERE name = $1
}
func (s *PostgresRBACStore) GetSubjectRoles(subject string) ([]string, error) {
    // SELECT role_name FROM subject_roles WHERE subject_id = $1
}
func (s *PostgresRBACStore) AssignRole(subject, role string) error {
    // INSERT INTO subject_roles (subject_id, role_name) VALUES ($1, $2) ON CONFLICT DO NOTHING
}
func (s *PostgresRBACStore) UnassignRole(subject, role string) error {
    // DELETE FROM subject_roles WHERE subject_id = $1 AND role_name = $2
}
func (s *PostgresRBACStore) AddRole(role rbac.Role) error {
    // UPSERT INTO roles ...
}
func (s *PostgresRBACStore) RemoveRole(name string) error {
    // DELETE FROM roles WHERE name = $1
}
```

### Rate Limit Store (Redis example skeleton)

```go
type RedisRateLimitStore struct{ client *redis.Client }

func (s *RedisRateLimitStore) Inc(key string, window time.Duration) (int64, error) {
    ctx := context.Background()
    pipe := s.client.Pipeline()
    incr := pipe.Incr(ctx, key)
    pipe.Expire(ctx, key, window)
    _, err := pipe.Exec(ctx)
    return incr.Val(), err
}
func (s *RedisRateLimitStore) Reset(key string) error {
    return s.client.Del(context.Background(), key).Err()
}
```

### JWT Blacklist (Redis example skeleton)

```go
type RedisBlacklist struct{ client *redis.Client }

func (b *RedisBlacklist) Revoke(token string) error {
    // Store with TTL equal to the token's remaining lifetime.
    // Parse expiry from the token claims first.
    ttl := timeUntilExpiry(token)
    return b.client.Set(context.Background(), "bl:"+token, 1, ttl).Err()
}
func (b *RedisBlacklist) IsRevoked(token string) (bool, error) {
    exists, err := b.client.Exists(context.Background(), "bl:"+token).Result()
    return exists > 0, err
}
```

### API Key Store (PostgreSQL example skeleton)

```go
type PostgresAPIKeyStore struct{ db *sql.DB }

func (s *PostgresAPIKeyStore) Save(k *apikey.Key) error {
    // INSERT INTO api_keys (id, hash, name, subject, metadata, expires_at) VALUES (...)
}
func (s *PostgresAPIKeyStore) GetByHash(hash string) (*apikey.Key, error) {
    // SELECT * FROM api_keys WHERE hash = $1
}
func (s *PostgresAPIKeyStore) GetByID(id string) (*apikey.Key, error) {
    // SELECT * FROM api_keys WHERE id = $1
}
func (s *PostgresAPIKeyStore) Revoke(id string) error {
    // UPDATE api_keys SET revoked = true WHERE id = $1
}
func (s *PostgresAPIKeyStore) ListBySubject(subject string) ([]*apikey.Key, error) {
    // SELECT * FROM api_keys WHERE subject = $1 ORDER BY created_at DESC
}
```

### Audit Logger (custom sink example)

```go
type DatadogLogger struct{ apiKey string }

func (l *DatadogLogger) Log(ctx context.Context, e audit.Event) error {
    payload, _ := json.Marshal(e)
    // POST payload to Datadog Logs API.
    return nil
}
```

---

## Error Reference

### auth/jwt errors

```go
jwtpkg.ErrExpiredToken          // token TTL elapsed — prompt re-login
jwtpkg.ErrInvalidToken          // malformed or bad signature — reject
jwtpkg.ErrTokenRevoked          // explicitly revoked — reject
jwtpkg.ErrInvalidSigningMethod  // algorithm mismatch — possible attack, log it
jwtpkg.ErrMissingAlgorithm      // programming error — no option passed to New()
jwtpkg.ErrNoBlacklist           // programming error — Revoke() called without WithBlacklist
```

### rbac errors

```go
rbac.ErrPermissionDenied        // Enforce() call — subject lacks permission
rbac.ErrRoleNotFound            // store lookup — role not in store
```

### abac errors

```go
abac.ErrPolicyNotFound          // RemovePolicy() — ID does not exist
// Evaluate() never returns an error — it returns Decision{Allowed: false} on deny
```

### apikey errors

```go
apikey.ErrInvalidKey            // key not found or hash mismatch
apikey.ErrRevokedKey            // key has been revoked
apikey.ErrExpiredKey            // key TTL has elapsed
apikey.ErrKeyNotFound           // store lookup by ID/hash returned nothing
```

### reqsign errors

```go
reqsign.ErrInvalidSignature     // HMAC mismatch
reqsign.ErrReplayDetected       // timestamp outside replay window
reqsign.ErrMissingHeader        // X-Signature or X-Timestamp header absent
```

### Error handling pattern

```go
claims, err := jwtSvc.Verify(token)
if err != nil {
    switch {
    case errors.Is(err, jwtpkg.ErrExpiredToken):
        // Ask client to refresh.
        http.Error(w, `{"error":"token_expired"}`, http.StatusUnauthorized)
    case errors.Is(err, jwtpkg.ErrTokenRevoked):
        // Force re-authentication.
        http.Error(w, `{"error":"token_revoked"}`, http.StatusUnauthorized)
    default:
        // Invalid token — no information to the client.
        http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
    }
    return
}
```

---

## Production Checklist

Use this checklist before shipping to production.

### JWT
- [ ] Secret is at least 32 bytes (HMAC) or use RSA/ECDSA for distributed systems
- [ ] Secret loaded from environment variable or secret manager, never hardcoded
- [ ] Token expiry set to ≤ 15 minutes for sensitive operations
- [ ] Blacklist backed by Redis (not `MemoryBlacklist`) in multi-instance deployments
- [ ] Refresh token rotation implemented (short-lived access + long-lived refresh)

### Passwords
- [ ] `passwdpolicy.Validate` called before `crypto.HashPassword` on all password inputs
- [ ] Argon2id parameters tuned for your hardware (benchmark: hash should take ~250ms)
- [ ] Password reset tokens generated with `crypto.GenerateToken(32)` and stored hashed

### RBAC / ABAC
- [ ] Roles and policies stored in a database, not hardcoded in memory
- [ ] RBAC `Store` and ABAC `PolicyStore` implementations are transactionally safe
- [ ] Default ABAC effect is `Deny` (do not use `WithDefaultAllow` without a catch-all deny policy)
- [ ] Test all permission boundaries — both allowed and denied cases

### API Keys
- [ ] Keys stored as SHA-256 hashes only — plaintext never persists
- [ ] Key expiry enforced for all third-party integrations
- [ ] Key listing endpoint restricted to the owning subject
- [ ] Revocation is immediate (no caching of key records)

### Rate Limiting
- [ ] `MemoryStore` replaced with Redis in multi-instance deployments
- [ ] Login endpoint has a significantly lower limit than general API endpoints
- [ ] `X-Forwarded-For` header trusted only behind a verified proxy/load balancer

### CORS
- [ ] `AllowAll()` removed; explicit `AllowedOrigins` list in place
- [ ] `AllowCredentials: true` only where explicitly required (cookies/auth header)

### Audit Logging
- [ ] Audit log sink is append-only and access-restricted
- [ ] All auth events logged (login, logout, failures, token revocation)
- [ ] Logs include request ID for correlation with application logs
- [ ] No sensitive data (passwords, raw tokens, PII) in log payloads

### Request Signing
- [ ] Webhook secrets are per-integration (different secret per external system)
- [ ] Replay window ≤ 5 minutes
- [ ] Signature verification errors are logged via `audit` package

### Secure Headers
- [ ] `secureheaders.Strict()` or `New(cfg)` applied at the outermost middleware layer
- [ ] HSTS `Preload: true` only after submitting domain to hstspreload.org
- [ ] CSP header configured if serving HTML (not needed for pure JSON APIs)

### TOTP / 2FA
- [ ] TOTP secrets stored encrypted at rest (use KMS or field-level encryption)
- [ ] Backup codes hashed with `crypto.HashPassword` before storage
- [ ] Used backup codes marked immediately to prevent reuse
- [ ] TOTP verification failure rate-limited (use `ratelimit` package)

### General
- [ ] All `MemoryStore` / `MemoryBlacklist` implementations replaced with persistent stores
- [ ] RSA/ECDSA private keys stored in a secret manager (Vault, AWS Secrets Manager, etc.)
- [ ] Error responses never leak internal details (stack traces, DB errors, key material)
- [ ] Integration tests cover the full middleware chain, not just individual handlers
