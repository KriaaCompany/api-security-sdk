// Package main demonstrates advanced usage of api-security-sdk:
// ECDSA-signed JWTs, ABAC policy evaluation, token revocation,
// and Argon2id password hashing.
//
// Run:
//
//	go run ./examples/advanced
package main

import (
	"crypto/elliptic"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/krishna/api-security-sdk/abac"
	jwtpkg "github.com/krishna/api-security-sdk/auth/jwt"
	authmw "github.com/krishna/api-security-sdk/auth/middleware"
	"github.com/krishna/api-security-sdk/crypto"
)

func main() {
	// ── Password hashing (Argon2id) ─────────────────────────────────────────
	hash, err := crypto.HashPassword("hunter2")
	if err != nil {
		log.Fatal(err)
	}
	ok, _ := crypto.VerifyPassword("hunter2", hash)
	log.Printf("password verified: %v", ok)

	// ── JWT with ECDSA P-256 (ES256) ─────────────────────────────────────────
	// In production: persist keys and load them from secure storage (e.g. Vault).
	privKey, pubKey, err := crypto.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		log.Fatal(err)
	}

	blacklist := jwtpkg.NewMemoryBlacklist()
	jwtSvc := jwtpkg.New(
		jwtpkg.WithECDSA(privKey, pubKey),
		jwtpkg.WithExpiry(15*time.Minute),
		jwtpkg.WithIssuer("advanced-example"),
		jwtpkg.WithBlacklist(blacklist),
	)

	// ── ABAC policies ────────────────────────────────────────────────────────
	policyStore := abac.NewMemoryStore()

	// Admins can do anything.
	_ = policyStore.AddPolicy(abac.Policy{
		ID:        "admin-all",
		Effect:    abac.Allow,
		Priority:  100,
		Condition: abac.SubjectHasRole("admin"),
	})

	// Explicit deny: no one may delete root-owned resources.
	_ = policyStore.AddPolicy(abac.Policy{
		ID:       "deny-root-delete",
		Effect:   abac.Deny,
		Priority: 90,
		Condition: abac.And(
			abac.ResourceAttrEquals("owner", "root"),
			abac.ActionIs("delete"),
		),
	})

	// Owners can read, update, and delete their own resources.
	_ = policyStore.AddPolicy(abac.Policy{
		ID:       "owner-access",
		Effect:   abac.Allow,
		Priority: 50,
		Condition: abac.And(
			abac.OwnerIsSubject(),
			abac.ActionIs("read", "update", "delete"),
		),
	})

	// Everyone can read publicly visible resources.
	_ = policyStore.AddPolicy(abac.Policy{
		ID:       "public-read",
		Effect:   abac.Allow,
		Priority: 10,
		Condition: abac.And(
			abac.ResourceAttrEquals("visibility", "public"),
			abac.ActionIs("read"),
		),
	})

	ev := abac.New(policyStore) // deny-by-default

	// ── Routes ───────────────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Issue tokens with custom claims (roles, etc.).
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user")
		role := r.URL.Query().Get("role")
		if userID == "" {
			http.Error(w, `{"error":"missing user"}`, http.StatusBadRequest)
			return
		}
		token, err := jwtSvc.Sign(jwtpkg.Claims{
			Subject: userID,
			Custom:  map[string]any{"roles": []string{role}},
		})
		if err != nil {
			http.Error(w, `{"error":"sign failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, token)
	})

	// Logout: revoke the token.
	mux.Handle("/logout",
		authmw.JWT(jwtSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the raw token from the header to revoke it.
			auth := r.Header.Get("Authorization")
			token := auth[len("Bearer "):]
			_ = jwtSvc.Revoke(token)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"message":"logged out"}`))
		})),
	)

	// Document endpoint: ABAC-protected.
	// The resource attributes would normally be loaded from a database using
	// a path parameter; here we hard-code a sample document.
	docHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := authmw.SubjectFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"access granted for %s"}`, subject)
	})

	mux.Handle("/documents/",
		authmw.JWT(jwtSvc)(
			abac.Require(
				ev,
				"read",
				func(r *http.Request) abac.Attributes {
					// In production: load the document from a DB using the path param.
					return abac.Attributes{
						"owner":      "alice",
						"visibility": "private",
					}
				},
				abac.SubjectFromClaims,
			)(docHandler),
		),
	)

	// Secure random token endpoint (example: CSRF or API key generation).
	mux.HandleFunc("/token/generate", func(w http.ResponseWriter, r *http.Request) {
		t, err := crypto.GenerateToken(32)
		if err != nil {
			http.Error(w, `{"error":"generation failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, t)
	})

	log.Println("Listening on :8080")
	log.Println("  GET  /login?user=<id>&role=<admin|user>  — issue ES256 token")
	log.Println("  POST /logout                             — revoke token")
	log.Println("  GET  /documents/<id>                     — ABAC-protected resource")
	log.Println("  GET  /token/generate                     — generate secure random token")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
