// Package main demonstrates the basic usage of api-security-sdk:
// JWT authentication with HMAC signing and RBAC authorisation.
//
// Run:
//
//	go run ./examples/basic
//
// Then:
//
//	# Get a token for "bob" (editor role)
//	TOKEN=$(curl -s 'http://localhost:8080/login?user=bob' | tr -d '"{}' | cut -d: -f2)
//
//	# Read posts (allowed — editor inherits viewer's read permission)
//	curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/posts
//
//	# Get a token for "carol" (viewer role) and try to create
//	TOKEN=$(curl -s 'http://localhost:8080/login?user=carol' | tr -d '"{}' | cut -d: -f2)
//	curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8080/posts  # → 403
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	jwtpkg "github.com/krishna/api-security-sdk/auth/jwt"
	authmw "github.com/krishna/api-security-sdk/auth/middleware"
	"github.com/krishna/api-security-sdk/rbac"
)

func main() {
	// ── JWT ─────────────────────────────────────────────────────────────────
	jwtSvc := jwtpkg.New(
		jwtpkg.WithHMAC([]byte("replace-with-a-secret-of-at-least-32-bytes!!")),
		jwtpkg.WithExpiry(15*time.Minute),
		jwtpkg.WithIssuer("basic-example"),
	)

	// ── RBAC ────────────────────────────────────────────────────────────────
	store := rbac.NewMemoryStore()

	_ = store.AddRole(rbac.Role{
		Name:        "admin",
		Permissions: []rbac.Permission{{Resource: "*", Action: "*"}},
	})
	_ = store.AddRole(rbac.Role{
		Name:        "viewer",
		Permissions: []rbac.Permission{{Resource: "*", Action: "read"}},
	})
	_ = store.AddRole(rbac.Role{
		Name:    "editor",
		Parents: []string{"viewer"}, // inherits read on everything
		Permissions: []rbac.Permission{
			{Resource: "posts", Action: "create"},
			{Resource: "posts", Action: "update"},
			{Resource: "posts", Action: "delete"},
		},
	})

	_ = store.AssignRole("alice", "admin")
	_ = store.AssignRole("bob", "editor")
	_ = store.AssignRole("carol", "viewer")

	enforcer := rbac.New(store)

	// ── Routes ──────────────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Public: issue a token (in production: verify credentials first)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user")
		if userID == "" {
			http.Error(w, `{"error":"missing user param"}`, http.StatusBadRequest)
			return
		}
		token, err := jwtSvc.Sign(jwtpkg.Claims{
			Subject: userID,
			Custom:  map[string]any{"email": userID + "@example.com"},
		})
		if err != nil {
			http.Error(w, `{"error":"could not sign token"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, token)
	})

	// Protected: JWT auth + RBAC (read posts)
	readHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := authmw.SubjectFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"hello %s, here are your posts","posts":[]}`, subject)
	})
	mux.Handle("/posts",
		authmw.JWT(jwtSvc)(
			rbac.Require(enforcer, "read", "posts")(readHandler),
		),
	)

	// Protected: JWT auth + RBAC (create post — editors and admins only)
	createHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := authmw.SubjectFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"post created by %s"}`, subject)
	})
	mux.Handle("/posts/create",
		authmw.JWT(jwtSvc)(
			rbac.Require(enforcer, "create", "posts")(createHandler),
		),
	)

	log.Println("Listening on :8080")
	log.Println("  GET  /login?user=<alice|bob|carol>  — issue token")
	log.Println("  GET  /posts                         — requires read:posts")
	log.Println("  POST /posts/create                  — requires create:posts")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
