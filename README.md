# api-security-sdk

A secure, fast, and easy-to-integrate Go SDK for authentication and authorisation. Drop it into any Go project to get JWT handling, Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), TOTP two-factor auth, API key management, rate limiting, and cryptographic utilities — with zero boilerplate.

## Features

- **JWT** — sign, verify, refresh, and revoke tokens with HMAC, RSA, or ECDSA
- **RBAC** — hierarchical roles with wildcard permissions and net/http middleware
- **ABAC** — composable policy conditions evaluated in priority order, deny-by-default
- **TOTP / 2FA** — RFC 6238 time-based one-time passwords, backup codes, QR provisioning URIs
- **API keys** — prefixed key generation, SHA-256 hashing, expiry, revocation, HTTP middleware
- **Rate limiting** — sliding-window counter with per-IP / per-subject / per-route key functions
- **Secure headers** — one-line HSTS, CSP, COEP/COOP/CORP, X-Frame-Options, and more
- **Crypto** — Argon2id password hashing, secure random tokens, RSA/ECDSA key helpers
- **Framework-agnostic** — standard `net/http` middleware; adapts to any router
- **Minimal dependencies** — only `golang-jwt/jwt/v5` and `golang.org/x/crypto`

## Installation

```sh
go get github.com/krishna/api-security-sdk
```

## Packages

| Import path | Purpose |
|---|---|
| `github.com/krishna/api-security-sdk/auth/jwt` | JWT service |
| `github.com/krishna/api-security-sdk/auth/middleware` | HTTP auth middleware & context helpers |
| `github.com/krishna/api-security-sdk/rbac` | Role-Based Access Control |
| `github.com/krishna/api-security-sdk/abac` | Attribute-Based Access Control |
| `github.com/krishna/api-security-sdk/otp` | TOTP two-factor authentication |
| `github.com/krishna/api-security-sdk/apikey` | API key generation & authentication |
| `github.com/krishna/api-security-sdk/ratelimit` | Sliding-window rate limiting |
| `github.com/krishna/api-security-sdk/secureheaders` | Security response headers middleware |
| `github.com/krishna/api-security-sdk/crypto` | Password hashing, tokens, key generation |

---

## JWT

### Setup

```go
import jwtpkg "github.com/krishna/api-security-sdk/auth/jwt"

// HMAC (symmetric) — simplest option
svc := jwtpkg.New(
    jwtpkg.WithHMAC([]byte("at-least-32-byte-secret!!")),
    jwtpkg.WithExpiry(15 * time.Minute),
    jwtpkg.WithIssuer("my-api"),
)

// RSA (asymmetric) — good for distributed systems
priv, pub, _ := crypto.GenerateRSAKeyPair(2048)
svc := jwtpkg.New(jwtpkg.WithRSA(priv, pub))

// ECDSA (asymmetric, smaller keys) — algorithm auto-detected from curve
priv, pub, _ := crypto.GenerateECDSAKeyPair(elliptic.P256()) // → ES256
svc := jwtpkg.New(jwtpkg.WithECDSA(priv, pub))
```

### Signing tokens

```go
token, err := svc.Sign(jwtpkg.Claims{
    Subject: "user-123",
    Custom: map[string]any{
        "email": "alice@example.com",
        "roles": []string{"admin", "editor"},
    },
})
```

### Verifying tokens

```go
claims, err := svc.Verify(token)
if err != nil {
    // jwtpkg.ErrExpiredToken, jwtpkg.ErrInvalidToken, etc.
}
fmt.Println(claims.Subject)          // "user-123"
fmt.Println(claims.Custom["email"]) // "alice@example.com"
```

### Refreshing tokens

```go
newToken, err := svc.Refresh(oldToken)
// The old token is revoked automatically if a blacklist is configured.
```

### Token revocation

```go
// Use the built-in in-memory blacklist (swap for a Redis-backed one in production).
blacklist := jwtpkg.NewMemoryBlacklist()
svc := jwtpkg.New(jwtpkg.WithHMAC(secret), jwtpkg.WithBlacklist(blacklist))

// Revoke a token (e.g. on logout).
svc.Revoke(token)

// Revoked tokens are rejected automatically by Verify.
_, err := svc.Verify(token) // → jwtpkg.ErrTokenRevoked
```

Implement the `jwtpkg.Blacklist` interface to back revocation with Redis, a database, or any other store.

---

## RBAC

### Setup

```go
import "github.com/krishna/api-security-sdk/rbac"

store := rbac.NewMemoryStore()

// Define roles. Use "*" as a wildcard for resource or action.
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
        {Resource: "posts", Action: "delete"},
    },
})
store.AddRole(rbac.Role{
    Name:        "admin",
    Permissions: []rbac.Permission{{Resource: "*", Action: "*"}},
})

// Assign roles to subjects (user IDs, service accounts, etc.).
store.AssignRole("alice", "admin")
store.AssignRole("bob", "editor")

enforcer := rbac.New(store)
```

### Checking permissions

```go
enforcer.Can("bob", "read", "posts")   // true  (inherited from viewer)
enforcer.Can("bob", "create", "posts") // true
enforcer.Can("bob", "delete", "users") // false

// Returns an error instead of a bool.
err := enforcer.Enforce("bob", "delete", "users")
// err == rbac.ErrPermissionDenied
```

### HTTP middleware

```go
import (
    authmw "github.com/krishna/api-security-sdk/auth/middleware"
    "github.com/krishna/api-security-sdk/rbac"
)

mux.Handle("/posts",
    authmw.JWT(jwtSvc)(             // 1. verify token, store claims in context
        rbac.Require(enforcer, "read", "posts")( // 2. enforce permission
            postsHandler,
        ),
    ),
)

// Require one of several roles (direct assignment check, no inheritance).
mux.Handle("/admin",
    authmw.JWT(jwtSvc)(
        rbac.RequireRole(enforcer, "admin")(adminHandler),
    ),
)
```

Implement the `rbac.Store` interface to back the store with PostgreSQL, Redis, or any other persistence layer.

---

## ABAC

ABAC evaluates structured policies against a request composed of subject, resource, action, and environment attributes. Policies are evaluated in descending priority order; the first match wins. Requests that match no policy are **denied** by default.

### Setup

```go
import "github.com/krishna/api-security-sdk/abac"

store := abac.NewMemoryStore()

// Admins can do anything.
store.AddPolicy(abac.Policy{
    ID:        "admin-all",
    Effect:    abac.Allow,
    Priority:  100,
    Condition: abac.SubjectHasRole("admin"),
})

// Explicit deny: protect root-owned resources from deletion by anyone.
store.AddPolicy(abac.Policy{
    ID:       "deny-root-delete",
    Effect:   abac.Deny,
    Priority: 90,
    Condition: abac.And(
        abac.ResourceAttrEquals("owner", "root"),
        abac.ActionIs("delete"),
    ),
})

// Owners can read, update, and delete their own resources.
store.AddPolicy(abac.Policy{
    ID:       "owner-access",
    Effect:   abac.Allow,
    Priority: 50,
    Condition: abac.And(
        abac.OwnerIsSubject(),
        abac.ActionIs("read", "update", "delete"),
    ),
})

// Anyone can read publicly visible resources.
store.AddPolicy(abac.Policy{
    ID:       "public-read",
    Effect:   abac.Allow,
    Priority: 10,
    Condition: abac.And(
        abac.ResourceAttrEquals("visibility", "public"),
        abac.ActionIs("read"),
    ),
})

ev := abac.New(store) // deny-by-default
// abac.New(store, abac.WithDefaultAllow()) — flip to allow-by-default
```

### Evaluating a request

```go
decision := ev.Evaluate(abac.Request{
    Subject:  abac.Attributes{"id": "alice", "roles": []string{"editor"}},
    Resource: abac.Attributes{"owner": "alice", "visibility": "private"},
    Action:   "update",
})
fmt.Println(decision.Allowed)       // true  (matched "owner-access")
fmt.Println(decision.MatchedPolicy) // "owner-access"

// Convenience wrapper.
ev.Allow(abac.Request{ ... }) // bool
```

### Built-in conditions

| Condition | Description |
|---|---|
| `ActionIs(actions...)` | Request action equals one of the given values |
| `SubjectAttrEquals(key, value)` | `subject[key] == value` |
| `ResourceAttrEquals(key, value)` | `resource[key] == value` |
| `EnvAttrEquals(key, value)` | `environment[key] == value` |
| `OwnerIsSubject()` | `resource["owner"] == subject["id"]` |
| `SubjectHasRole(role)` | subject has the given role (string or `[]string`) |
| `And(conditions...)` | All conditions must match |
| `Or(conditions...)` | At least one condition must match |
| `Not(condition)` | Negates a condition |

Custom conditions are plain functions:

```go
abac.Policy{
    Condition: func(req abac.Request) bool {
        // any logic here
        return req.Environment["ip"] == "127.0.0.1"
    },
}
```

### HTTP middleware

```go
mux.Handle("/documents/",
    authmw.JWT(jwtSvc)(
        abac.Require(
            ev,
            "read",
            func(r *http.Request) abac.Attributes {
                // load the resource being accessed (e.g. from DB)
                id := strings.TrimPrefix(r.URL.Path, "/documents/")
                doc := db.GetDocument(id)
                return abac.Attributes{"owner": doc.OwnerID, "visibility": doc.Visibility}
            },
            abac.SubjectFromClaims, // maps JWT claims → subject attributes
        )(docHandler),
    ),
)
```

---

## TOTP / Two-Factor Authentication

RFC 6238 time-based one-time passwords, compatible with Google Authenticator, Authy, 1Password, and any standard authenticator app. Implemented using the Go standard library only — no extra dependencies.

### Setup flow

```go
import "github.com/krishna/api-security-sdk/otp"

// 1. Generate a secret during account setup. Store it encrypted per user.
secret, err := otp.NewSecret()

// 2. Build a provisioning URI and render it as a QR code for the user to scan.
uri := otp.ProvisioningURI("alice@example.com", "MyApp", secret)
// Pass uri to any QR code library, e.g. github.com/skip2/go-qrcode

// 3. On every login, verify the code from the user's authenticator app.
ok, err := otp.Verify(secret, userSuppliedCode)
if err != nil || !ok {
    // reject login
}
```

### Backup codes

```go
// Generate 10 single-use backup codes (show once, store hashed).
codes, err := otp.GenerateBackupCodes(10)
// codes[i] looks like "A3K9M-X7P2Q"
// Hash each code with crypto.HashPassword before storing.
```

### Custom parameters

```go
ok, err := otp.VerifyWithOptions(secret, code, otp.VerifyOptions{
    Digits: 8,           // 8-digit codes
    Period: 60,          // 60-second window
    Skew:   2,           // allow ±2 windows of clock drift
})
```

---

## API Keys

Prefixed, base62-encoded API keys with SHA-256 hashing for safe storage. Only the hash is ever persisted; a leaked database cannot expose plaintext keys.

### Issuing keys

```go
import "github.com/krishna/api-security-sdk/apikey"

store := apikey.NewMemoryStore()
svc   := apikey.NewService(store)

issued, err := svc.Issue(apikey.IssueOptions{
    Prefix:    "sk_live",           // key looks like "sk_live_A3Bx…"
    Name:      "ci-pipeline",
    Subject:   "user-123",          // link key to a user/service
    ExpiresIn: 90 * 24 * time.Hour, // optional TTL
})
fmt.Println(issued.Plaintext) // show to user ONCE — never stored
```

### Verifying keys

```go
key, err := svc.Verify(plaintextKeyFromRequest)
// err is apikey.ErrInvalidKey, ErrRevokedKey, or ErrExpiredKey on failure.
fmt.Println(key.Subject) // "user-123"
```

### Revoking keys

```go
svc.Revoke(key.ID)
```

### HTTP middleware

The middleware reads the key from `X-API-Key` or `Authorization: Bearer <key>`.

```go
mux.Handle("/api/",
    apikey.Middleware(svc)(handler),
)

// Retrieve the verified key record inside a handler:
k := apikey.KeyFrom(r.Context())   // *apikey.Key
s := apikey.SubjectFrom(r.Context()) // string
```

---

## Rate Limiting

Sliding-window counter rate limiter with standard `X-RateLimit-*` response headers and a `429 Too Many Requests` response on breach.

### Basic usage

```go
import "github.com/krishna/api-security-sdk/ratelimit"

store   := ratelimit.NewMemoryStore()
limiter := ratelimit.New(store, ratelimit.Config{
    Limit:  100,
    Window: time.Minute,
})
mux.Handle("/api/", limiter(handler))
```

### Key functions

Rate-limit by IP (default), authenticated subject, or URL path:

```go
// Per authenticated user (falls back to IP for anonymous requests).
import authmw "github.com/krishna/api-security-sdk/auth/middleware"

limiter := ratelimit.New(store, ratelimit.Config{
    Limit:  1000,
    Window: time.Hour,
    KeyFn:  ratelimit.BySubject(authmw.SubjectFrom),
})

// Per route (different limits without separate middleware instances).
ratelimit.New(store, ratelimit.Config{Limit: 20, Window: time.Minute, KeyFn: ratelimit.ByRoute})
```

### Response headers

Every response receives:

| Header | Value |
|---|---|
| `X-RateLimit-Limit` | Configured request limit |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |
| `Retry-After` | Seconds to wait (only on 429 responses) |

---

## Secure Headers

A single middleware call that sets modern security response headers. Apply it once at the outermost layer of your stack.

### Strict preset (recommended)

```go
import "github.com/krishna/api-security-sdk/secureheaders"

mux.Handle("/", secureheaders.Strict()(handler))
```

`Strict()` sets HSTS (1 year, includeSubDomains), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, COEP/COOP/CORP, and removes the `Server` and `X-Powered-By` headers.

### Custom configuration

```go
mux.Handle("/", secureheaders.New(secureheaders.Config{
    HSTS: secureheaders.HSTSConfig{
        MaxAge:            365 * 24 * time.Hour,
        IncludeSubDomains: true,
        Preload:           true, // only after submitting to hstspreload.org
    },
    ContentTypeOpts:   true,
    FrameOptions:      "SAMEORIGIN",
    CSP:               "default-src 'self'; img-src *",
    ReferrerPolicy:    "strict-origin-when-cross-origin",
    PermissionsPolicy: "geolocation=(), microphone=()",
    COEP:              "require-corp",
    COOP:              "same-origin",
    CORP:              "same-origin",
    RemoveServerHeader: true,
})(handler))
```

---

## Crypto

### Password hashing (Argon2id)

```go
import "github.com/krishna/api-security-sdk/crypto"

// Hash a password. The returned string is self-contained (PHC format)
// and safe to store directly in a database column.
hash, err := crypto.HashPassword("correct-horse-battery-staple")

// Verify a password against a stored hash. Uses constant-time comparison.
ok, err := crypto.VerifyPassword("correct-horse-battery-staple", hash)
```

Tune the parameters for your hardware:

```go
hash, err := crypto.HashPasswordWithConfig("password", crypto.PasswordConfig{
    Memory:      128 * 1024, // 128 MiB
    Iterations:  4,
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
})
```

### Secure random tokens

```go
// 32 bytes → 256 bits of entropy, base64url encoded (no padding).
// Suitable for session tokens, CSRF tokens, and API keys.
token, err := crypto.GenerateToken(32)
```

### RSA & ECDSA key generation

```go
// Generate and PEM-encode an RSA key pair.
priv, pub, err := crypto.GenerateRSAKeyPair(2048)
privPEM, _ := crypto.RSAPrivateKeyToPEM(priv)
pubPEM, _  := crypto.RSAPublicKeyToPEM(pub)

// Generate an ECDSA key pair (P-256, P-384, or P-521).
priv, pub, err := crypto.GenerateECDSAKeyPair(elliptic.P256())

// Parse PEM back to key objects.
priv, err := crypto.ParseRSAPrivateKeyPEM(privPEM)
priv, err := crypto.ParseECDSAPrivateKeyPEM(privPEM)
```

---

## HTTP middleware reference

### `auth/middleware`

| Function | Description |
|---|---|
| `JWT(svc, opts...)` | Validate Bearer token; store claims in context. Returns 401 on failure. |
| `Optional(svc)` | Like `JWT` but passes through requests with no or invalid token. |
| `RequireAuth(...)` | Reject requests with no claims in context. Pair after `Optional`. |
| `ClaimsFrom(ctx)` | Retrieve `*jwt.Claims` from a request context. |
| `SubjectFrom(ctx)` | Retrieve the token subject string from a request context. |
| `CustomClaimFrom(ctx, key)` | Retrieve a single custom claim value from a request context. |

### `rbac`

| Function | Description |
|---|---|
| `Require(enforcer, action, resource)` | 403 unless subject can perform action on resource. |
| `RequireRole(enforcer, roles...)` | 403 unless subject has at least one of the given roles. |

### `abac`

| Function | Description |
|---|---|
| `Require(ev, action, resourceFn, subjectFn)` | 403 unless ABAC evaluator allows the request. |
| `SubjectFromClaims` | Pre-built `subjectFn` that maps JWT claims to `Attributes`. |

### `ratelimit`

| Function | Description |
|---|---|
| `New(store, cfg)` | Sliding-window rate limiter; 429 on breach with `X-RateLimit-*` headers. |
| `ByIP(r)` | Default `KeyFn` — rate-limits per client IP. |
| `BySubject(subjectFn)` | Rate-limits per authenticated subject, falls back to IP. |
| `ByRoute(r)` | Rate-limits per IP + URL path combination. |

### `apikey`

| Function | Description |
|---|---|
| `Middleware(svc, opts...)` | 401 unless a valid API key is present in `X-API-Key` or `Authorization`. |
| `KeyFrom(ctx)` | Retrieve `*apikey.Key` from a request context. |
| `SubjectFrom(ctx)` | Retrieve the key's subject string from a request context. |

### `secureheaders`

| Function | Description |
|---|---|
| `Strict()` | Apply opinionated production-grade security headers. |
| `New(cfg)` | Apply a custom header configuration. |

---

## Extending with your own stores

Every stateful component is backed by an interface. Swap the in-memory implementations for database-backed ones without changing any application code.

```go
// Implement rbac.Store to persist roles in PostgreSQL, Redis, etc.
type MyRBACStore struct { db *sql.DB }
func (s *MyRBACStore) GetRole(name string) (rbac.Role, error)            { ... }
func (s *MyRBACStore) GetSubjectRoles(subject string) ([]string, error)  { ... }
func (s *MyRBACStore) AssignRole(subject, role string) error             { ... }
func (s *MyRBACStore) UnassignRole(subject, role string) error           { ... }
func (s *MyRBACStore) AddRole(role rbac.Role) error                      { ... }
func (s *MyRBACStore) RemoveRole(name string) error                      { ... }

enforcer := rbac.New(&MyRBACStore{db: db})
```

The same pattern applies to `abac.PolicyStore`, `jwt.Blacklist`, `apikey.Store`, and `ratelimit.Store`.

---

## Running the examples

```sh
# Basic: HMAC JWT + RBAC
go run ./examples/basic

# Advanced: ECDSA JWT + ABAC + revocation + password hashing
go run ./examples/advanced
```

---

## Security notes

- **HMAC secrets** must be at least 32 bytes. Shorter secrets will be accepted but provide reduced security.
- **RSA keys** should be at least 2048 bits; prefer 4096 for long-lived keys.
- **Argon2id defaults** follow OWASP recommendations (64 MiB memory, 3 iterations, parallelism 2). Tune upward for sensitive data.
- The `MemoryBlacklist` and `MemoryStore` types are suitable for single-process deployments and testing. Use a shared store (Redis, database) in horizontally-scaled environments.
- ABAC is **deny-by-default** — requests that match no policy are rejected. Call `abac.WithDefaultAllow()` only when you have an explicit deny-all catch-all policy.
- **API key hashes** use SHA-256, which is appropriate here because the keys are long, high-entropy random strings. Do not use SHA-256 to hash passwords — use `crypto.HashPassword` (Argon2id) for that.
- **TOTP secrets** must be stored encrypted at rest. Use your KMS or a field-level encryption library; do not store them as plaintext.
- **Rate limiting** with `MemoryStore` is per-process. In a multi-instance deployment, use a Redis-backed `ratelimit.Store` so limits are enforced across the fleet.
- **Secure headers** — do not set `Preload: true` on HSTS unless you have submitted your domain at [hstspreload.org](https://hstspreload.org) and are prepared to serve all traffic over HTTPS permanently.
