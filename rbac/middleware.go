package rbac

import (
	"net/http"

	authmw "github.com/KriaaCompany/api-security-sdk/auth/middleware"
)

// Require returns HTTP middleware that enforces a single RBAC permission.
// The subject is taken from the JWT claims stored in the request context, so
// the JWT middleware must run before this one.
//
// Usage:
//
//	mux.Handle("/posts", authmw.JWT(svc)(rbac.Require(enforcer, "read", "posts")(handler)))
func Require(enforcer *Enforcer, action, resource string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := authmw.SubjectFrom(r.Context())
			if subject == "" || !enforcer.Can(subject, action, resource) {
				writeForbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns HTTP middleware that passes only when the authenticated
// subject has been directly assigned at least one of the given role names.
//
// Usage:
//
//	mux.Handle("/admin", authmw.JWT(svc)(rbac.RequireRole(enforcer, "admin")(handler)))
func RequireRole(enforcer *Enforcer, roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := authmw.SubjectFrom(r.Context())
			if subject == "" {
				writeForbidden(w)
				return
			}
			assigned, err := enforcer.RolesFor(subject)
			if err != nil {
				writeForbidden(w)
				return
			}
			for _, want := range roles {
				for _, have := range assigned {
					if want == have {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
			writeForbidden(w)
		})
	}
}

func writeForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden"}`))
}
