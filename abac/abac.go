// Package abac provides Attribute-Based Access Control (ABAC) policy evaluation.
//
// Policies are predicates (Condition functions) paired with an Allow or Deny
// effect. The Evaluator applies policies in descending priority order; the
// first matching policy wins. When no policy matches, the default effect
// (Deny) is used — this is "deny-by-default" and is the secure default.
//
// Quick start:
//
//	store := abac.NewMemoryStore()
//	store.AddPolicy(abac.Policy{
//	    ID:       "owner-can-edit",
//	    Effect:   abac.Allow,
//	    Priority: 10,
//	    Condition: abac.And(abac.OwnerIsSubject(), abac.ActionIs("read", "update")),
//	})
//
//	ev := abac.New(store)
//	decision := ev.Evaluate(abac.Request{
//	    Subject:  abac.Attributes{"id": "alice"},
//	    Resource: abac.Attributes{"owner": "alice"},
//	    Action:   "read",
//	})
package abac

// Evaluator evaluates access requests against a PolicyStore.
type Evaluator struct {
	store         PolicyStore
	defaultEffect Effect
}

// EvaluatorOption configures an Evaluator.
type EvaluatorOption func(*Evaluator)

// WithDefaultAllow changes the default decision to Allow when no policy matches.
// Use with caution — deny-by-default is the safer choice for most applications.
func WithDefaultAllow() EvaluatorOption {
	return func(e *Evaluator) { e.defaultEffect = Allow }
}

// New creates an Evaluator backed by the given PolicyStore.
// The default behaviour is to deny requests that match no policy.
func New(store PolicyStore, opts ...EvaluatorOption) *Evaluator {
	ev := &Evaluator{store: store, defaultEffect: Deny}
	for _, o := range opts {
		o(ev)
	}
	return ev
}

// Evaluate runs req against all policies and returns a Decision.
// Policies are evaluated in descending priority order. The first matching
// policy determines the outcome. If no policy matches, the configured default
// effect is applied.
func (ev *Evaluator) Evaluate(req Request) Decision {
	policies, err := ev.store.Policies()
	if err != nil {
		return Decision{Allowed: ev.defaultEffect == Allow}
	}
	for _, p := range policies {
		if p.Condition == nil || p.Condition(req) {
			return Decision{
				Allowed:       p.Effect == Allow,
				MatchedPolicy: p.ID,
			}
		}
	}
	return Decision{Allowed: ev.defaultEffect == Allow}
}

// Allow is a convenience wrapper that returns true when the request is permitted.
func (ev *Evaluator) Allow(req Request) bool {
	return ev.Evaluate(req).Allowed
}
