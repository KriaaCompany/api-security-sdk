package abac

import (
	"net/http"

	authmw "github.com/KriaaCompany/api-security-sdk/auth/middleware"
)

// Require returns HTTP middleware that enforces an ABAC policy.
//
// Parameters:
//   - ev: the Evaluator to use.
//   - action: the operation being performed (e.g. "read").
//   - resourceFn: builds the resource Attributes from the request; may be nil.
//   - subjectFn: builds the subject Attributes from the request.
//
// The Environment attributes are populated automatically with the remote
// address, HTTP method, and URL path.
//
// Usage:
//
//	mux.Handle("/docs/",
//	    authmw.JWT(svc)(
//	        abac.Require(ev, "read",
//	            func(r *http.Request) abac.Attributes { return loadDoc(r) },
//	            abac.SubjectFromClaims,
//	        )(handler),
//	    ),
//	)
func Require(
	ev *Evaluator,
	action string,
	resourceFn func(*http.Request) Attributes,
	subjectFn func(*http.Request) Attributes,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var resource Attributes
			if resourceFn != nil {
				resource = resourceFn(r)
			}
			if resource == nil {
				resource = Attributes{}
			}

			req := Request{
				Action:   action,
				Subject:  subjectFn(r),
				Resource: resource,
				Environment: Attributes{
					"ip":     r.RemoteAddr,
					"method": r.Method,
					"path":   r.URL.Path,
				},
			}
			if !ev.Allow(req) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SubjectFromClaims is a pre-built subject function that maps JWT claims
// stored in the request context into an Attributes map.
// It sets "id" to the subject claim and merges all custom claims.
//
// Pass this as the subjectFn argument to Require when using JWT auth.
func SubjectFromClaims(r *http.Request) Attributes {
	claims := authmw.ClaimsFrom(r.Context())
	if claims == nil {
		return Attributes{}
	}
	attrs := Attributes{"id": claims.Subject}
	for k, v := range claims.Custom {
		attrs[k] = v
	}
	return attrs
}
