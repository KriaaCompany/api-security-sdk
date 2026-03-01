package abac

// Effect is the outcome of a policy match.
type Effect int

const (
	// Allow grants the request.
	Allow Effect = iota
	// Deny explicitly rejects the request (takes precedence over Allow at equal priority).
	Deny
)

// Attributes is a generic map of named values attached to a subject, resource, or environment.
type Attributes map[string]any

// Request is the input to a policy evaluation.
type Request struct {
	// Subject is the entity requesting access (e.g. the authenticated user).
	Subject Attributes
	// Resource is the object being accessed (e.g. a document or API endpoint).
	Resource Attributes
	// Action is the operation being performed (e.g. "read", "delete").
	Action string
	// Environment holds contextual attributes (e.g. IP address, time of day).
	Environment Attributes
}

// Decision is the outcome of evaluating a request against the policy store.
type Decision struct {
	// Allowed is true when access is permitted.
	Allowed bool
	// MatchedPolicy is the ID of the first policy that matched, or empty if none did.
	MatchedPolicy string
}

// Policy defines a rule that maps a predicate (Condition) to an Effect.
type Policy struct {
	// ID uniquely identifies the policy and appears in Decision.MatchedPolicy.
	ID string
	// Effect is applied when Condition returns true.
	Effect Effect
	// Condition determines whether this policy applies to a given request.
	// A nil Condition matches every request.
	Condition Condition
	// Priority controls evaluation order; higher values are evaluated first.
	Priority int
}

// Condition is a predicate over a Request. It returns true when the policy applies.
type Condition func(req Request) bool

// ─── Condition combinators ────────────────────────────────────────────────────

// And returns a Condition that is true only when all provided conditions are true.
func And(conditions ...Condition) Condition {
	return func(req Request) bool {
		for _, c := range conditions {
			if !c(req) {
				return false
			}
		}
		return true
	}
}

// Or returns a Condition that is true when at least one provided condition is true.
func Or(conditions ...Condition) Condition {
	return func(req Request) bool {
		for _, c := range conditions {
			if c(req) {
				return true
			}
		}
		return false
	}
}

// Not negates a condition.
func Not(condition Condition) Condition {
	return func(req Request) bool {
		return !condition(req)
	}
}

// ─── Built-in conditions ──────────────────────────────────────────────────────

// ActionIs returns a Condition that matches when Request.Action equals one of the given values.
func ActionIs(actions ...string) Condition {
	set := make(map[string]bool, len(actions))
	for _, a := range actions {
		set[a] = true
	}
	return func(req Request) bool {
		return set[req.Action]
	}
}

// SubjectAttrEquals returns a Condition that is true when subject[key] == value.
func SubjectAttrEquals(key string, value any) Condition {
	return func(req Request) bool {
		return req.Subject[key] == value
	}
}

// ResourceAttrEquals returns a Condition that is true when resource[key] == value.
func ResourceAttrEquals(key string, value any) Condition {
	return func(req Request) bool {
		return req.Resource[key] == value
	}
}

// OwnerIsSubject returns a Condition that is true when resource["owner"] == subject["id"].
func OwnerIsSubject() Condition {
	return func(req Request) bool {
		owner, _ := req.Resource["owner"].(string)
		subjectID, _ := req.Subject["id"].(string)
		return owner != "" && owner == subjectID
	}
}

// SubjectHasRole returns a Condition that checks for a role value in subject["roles"].
// It accepts both a []string and a plain string value for subject["roles"].
func SubjectHasRole(role string) Condition {
	return func(req Request) bool {
		switch v := req.Subject["roles"].(type) {
		case []string:
			for _, r := range v {
				if r == role {
					return true
				}
			}
		case string:
			return v == role
		}
		return false
	}
}

// EnvAttrEquals returns a Condition that is true when environment[key] == value.
func EnvAttrEquals(key string, value any) Condition {
	return func(req Request) bool {
		return req.Environment[key] == value
	}
}
