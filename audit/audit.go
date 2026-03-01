// Package audit provides structured security event logging for authentication
// and authorisation actions. It is designed for compliance requirements such as
// SOC 2, ISO 27001, and GDPR audit trails.
//
// Quick start:
//
//	logger := audit.NewJSONLogger(os.Stdout)
//	logger.Log(ctx, audit.Event{
//	    Type:    audit.EventLogin,
//	    Subject: "user-123",
//	    Result:  audit.ResultAllow,
//	    IP:      "1.2.3.4",
//	})
//
// Middleware integration:
//
//	mux.Handle("/", audit.Middleware(logger)(handler))
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// ─── Event types ─────────────────────────────────────────────────────────────

// EventType classifies a security-relevant action.
type EventType string

const (
	// Authentication events.
	EventLogin       EventType = "auth.login"
	EventLoginFailed EventType = "auth.login_failed"
	EventLogout      EventType = "auth.logout"
	EventMFASuccess  EventType = "auth.mfa_success"
	EventMFAFailed   EventType = "auth.mfa_failed"

	// Token lifecycle.
	EventTokenIssued   EventType = "token.issued"
	EventTokenVerified EventType = "token.verified"
	EventTokenRefreshed EventType = "token.refreshed"
	EventTokenRevoked  EventType = "token.revoked"
	EventTokenExpired  EventType = "token.expired"
	EventTokenInvalid  EventType = "token.invalid"

	// API key lifecycle.
	EventAPIKeyIssued  EventType = "apikey.issued"
	EventAPIKeyUsed    EventType = "apikey.used"
	EventAPIKeyRevoked EventType = "apikey.revoked"
	EventAPIKeyInvalid EventType = "apikey.invalid"

	// Authorisation decisions.
	EventAccessGranted EventType = "authz.access_granted"
	EventAccessDenied  EventType = "authz.access_denied"

	// Rate limiting.
	EventRateLimited EventType = "rate.limited"

	// Account management.
	EventPasswordChanged EventType = "account.password_changed"
	EventPasswordReset   EventType = "account.password_reset"
	EventAccountLocked   EventType = "account.locked"
	EventAccountUnlocked EventType = "account.unlocked"
)

// Result is the outcome of a security event.
type Result string

const (
	ResultAllow   Result = "allow"
	ResultDeny    Result = "deny"
	ResultUnknown Result = "unknown"
)

// ─── Event ───────────────────────────────────────────────────────────────────

// Event represents a single auditable security action.
type Event struct {
	// ID is a unique identifier for this event (set automatically by JSONLogger
	// if left empty — applications may set their own).
	ID string `json:"id,omitempty"`

	// Type classifies the event.
	Type EventType `json:"type"`

	// Timestamp is when the event occurred. Defaults to time.Now() when zero.
	Timestamp time.Time `json:"timestamp"`

	// Subject is the entity that performed the action (user ID, service name, etc.).
	Subject string `json:"subject,omitempty"`

	// Resource is the object that was acted upon (e.g. "posts/42", "users").
	Resource string `json:"resource,omitempty"`

	// Action is the operation that was attempted (e.g. "read", "delete").
	Action string `json:"action,omitempty"`

	// Result is the outcome of the event.
	Result Result `json:"result,omitempty"`

	// IP is the client IP address.
	IP string `json:"ip,omitempty"`

	// UserAgent is the client User-Agent string.
	UserAgent string `json:"user_agent,omitempty"`

	// RequestID correlates the event with an HTTP request trace.
	RequestID string `json:"request_id,omitempty"`

	// Meta holds arbitrary additional fields.
	Meta map[string]any `json:"meta,omitempty"`
}

// ─── Logger interface ─────────────────────────────────────────────────────────

// Logger is the sink for audit events.
type Logger interface {
	Log(ctx context.Context, event Event) error
}

// ─── JSON logger ─────────────────────────────────────────────────────────────

// JSONLogger writes newline-delimited JSON events to an io.Writer.
// Each event is a single JSON object terminated by a newline — compatible with
// log aggregators such as Loki, Datadog, CloudWatch, and Splunk.
type JSONLogger struct {
	w   io.Writer
	enc *json.Encoder
}

// NewJSONLogger creates a JSONLogger that writes to w.
func NewJSONLogger(w io.Writer) *JSONLogger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONLogger{w: w, enc: enc}
}

// Log writes event as a JSON line. It auto-populates Timestamp when zero.
func (l *JSONLogger) Log(_ context.Context, e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	return l.enc.Encode(e)
}

// ─── Multi logger ─────────────────────────────────────────────────────────────

// MultiLogger fans out events to multiple loggers. All loggers are called even
// when one returns an error; the first error is returned.
type MultiLogger struct {
	loggers []Logger
}

// NewMultiLogger creates a MultiLogger that writes to all provided loggers.
func NewMultiLogger(loggers ...Logger) *MultiLogger {
	return &MultiLogger{loggers: loggers}
}

// Log sends the event to every configured logger.
func (m *MultiLogger) Log(ctx context.Context, e Event) error {
	var first error
	for _, l := range m.loggers {
		if err := l.Log(ctx, e); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// ─── NOOP logger ──────────────────────────────────────────────────────────────

// NOOPLogger discards all events. Useful in tests or when audit logging is
// optional.
type NOOPLogger struct{}

// Log does nothing and returns nil.
func (NOOPLogger) Log(_ context.Context, _ Event) error { return nil }

// ─── Context helpers ──────────────────────────────────────────────────────────

type loggerKey struct{}

// WithLogger stores a Logger in the context so handlers can retrieve it without
// explicit dependency injection.
func WithLogger(ctx context.Context, l Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

// FromContext retrieves the Logger from the context. Returns NOOPLogger when
// no logger is present, so callers never need to nil-check.
func FromContext(ctx context.Context) Logger {
	if l, ok := ctx.Value(loggerKey{}).(Logger); ok {
		return l
	}
	return NOOPLogger{}
}

// Log is a convenience shorthand for FromContext(ctx).Log(ctx, event).
func Log(ctx context.Context, event Event) error {
	return FromContext(ctx).Log(ctx, event)
}

// ─── HTTP middleware ──────────────────────────────────────────────────────────

// Middleware injects the logger into the request context and, optionally, logs
// every request automatically when logRequests is true. The logged event type
// is EventAccessGranted or EventAccessDenied based on the response status code
// (status ≥ 400 is treated as denied).
//
// Usage — inject only (log manually inside handlers):
//
//	mux.Handle("/", audit.Middleware(logger)(handler))
//
// Usage — auto-log every request:
//
//	mux.Handle("/", audit.Middleware(logger, true)(handler))
func Middleware(l Logger, logRequests ...bool) func(http.Handler) http.Handler {
	autoLog := len(logRequests) > 0 && logRequests[0]
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithLogger(r.Context(), l)
			r = r.WithContext(ctx)

			if !autoLog {
				next.ServeHTTP(w, r)
				return
			}

			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			result := ResultAllow
			if rw.status >= 400 {
				result = ResultDeny
			}
			_ = l.Log(ctx, Event{
				Type:      eventTypeForStatus(rw.status),
				Timestamp: time.Now().UTC(),
				Resource:  r.URL.Path,
				Action:    r.Method,
				Result:    result,
				IP:        remoteIP(r),
				UserAgent: r.UserAgent(),
				RequestID: r.Header.Get("X-Request-Id"),
				Meta:      map[string]any{"status": rw.status},
			})
		})
	}
}

func eventTypeForStatus(status int) EventType {
	if status >= 400 {
		return EventAccessDenied
	}
	return EventAccessGranted
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := indexOf(xff, ','); i >= 0 {
			return xff[:i]
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Eventf is a convenience constructor for quickly building events.
//
//	audit.Eventf(audit.EventLogin, "user-123", audit.ResultAllow).WithIP("1.2.3.4")
func Eventf(t EventType, subject string, result Result) *EventBuilder {
	return &EventBuilder{e: Event{
		Type:      t,
		Subject:   subject,
		Result:    result,
		Timestamp: time.Now().UTC(),
	}}
}

// EventBuilder provides a fluent API for constructing Events.
type EventBuilder struct {
	e Event
}

func (b *EventBuilder) WithResource(resource string) *EventBuilder {
	b.e.Resource = resource
	return b
}
func (b *EventBuilder) WithAction(action string) *EventBuilder {
	b.e.Action = action
	return b
}
func (b *EventBuilder) WithIP(ip string) *EventBuilder {
	b.e.IP = ip
	return b
}
func (b *EventBuilder) WithMeta(key string, value any) *EventBuilder {
	if b.e.Meta == nil {
		b.e.Meta = make(map[string]any)
	}
	b.e.Meta[key] = value
	return b
}
func (b *EventBuilder) WithRequestID(id string) *EventBuilder {
	b.e.RequestID = id
	return b
}

// Build returns the constructed Event.
func (b *EventBuilder) Build() Event { return b.e }

// Log sends the event to the logger in ctx and returns any error.
func (b *EventBuilder) Log(ctx context.Context) error {
	return FromContext(ctx).Log(ctx, b.e)
}

// Logf is a shorthand: build and log in one call, returning a formatted error
// string if logging fails (safe to ignore in non-critical paths).
func (b *EventBuilder) Logf(ctx context.Context) string {
	if err := b.Log(ctx); err != nil {
		return fmt.Sprintf("audit: failed to log event: %v", err)
	}
	return ""
}
