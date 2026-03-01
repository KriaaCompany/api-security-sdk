// Package reqsign provides HMAC-SHA256 request signing and verification for
// service-to-service authentication and webhook delivery.
//
// # Signing model
//
// The signed payload is:
//
//	<unix-timestamp-seconds>\n<request-body>
//
// The HMAC-SHA256 of this payload (keyed with the shared secret) is transmitted
// in the request header as a hex string. The timestamp binds the signature to a
// specific point in time; the verifier rejects signatures outside a configurable
// replay window (default ±5 minutes).
//
// This is the same scheme used by Stripe, GitHub, and Twilio webhooks.
//
// # Outbound (signing)
//
//	transport := reqsign.NewSigningTransport([]byte("shared-secret"), nil)
//	client := &http.Client{Transport: transport}
//	client.Post(url, "application/json", body)
//
// # Inbound (verification)
//
//	mux.Handle("/webhook", reqsign.Middleware([]byte("shared-secret"))(handler))
package reqsign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultHeader is the request header carrying the signature.
	DefaultHeader = "X-Signature"
	// DefaultTimestampHeader carries the Unix timestamp used in the signature.
	DefaultTimestampHeader = "X-Timestamp"
	// DefaultReplayWindow is the maximum age of an accepted signature.
	DefaultReplayWindow = 5 * time.Minute
)

// ErrInvalidSignature is returned when a request signature does not match.
var ErrInvalidSignature = errors.New("reqsign: invalid signature")

// ErrReplayDetected is returned when the request timestamp is outside the
// replay window, indicating a potential replay attack.
var ErrReplayDetected = errors.New("reqsign: timestamp outside replay window")

// ErrMissingHeader is returned when the expected signature headers are absent.
var ErrMissingHeader = errors.New("reqsign: missing signature header")

// ─── Signing ──────────────────────────────────────────────────────────────────

// Sign computes an HMAC-SHA256 signature over "<timestamp>\n<body>" using
// the given secret. Returns the hex-encoded signature.
func Sign(secret, body []byte, timestamp time.Time) string {
	return sign(secret, body, timestamp.Unix())
}

func sign(secret, body []byte, ts int64) string {
	payload := buildPayload(ts, body)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks whether sig is the correct HMAC-SHA256 signature of body at
// the given timestamp. Uses constant-time comparison to prevent timing attacks.
func Verify(secret, body []byte, timestamp time.Time, sig string) bool {
	expected := Sign(secret, body, timestamp)
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	expectedBytes, _ := hex.DecodeString(expected)
	return hmac.Equal(sigBytes, expectedBytes)
}

// ─── Middleware (inbound verification) ───────────────────────────────────────

// VerifyOptions configures the inbound verification middleware.
type VerifyOptions struct {
	// Header is the request header carrying the hex signature.
	// Defaults to DefaultHeader ("X-Signature").
	Header string
	// TimestampHeader is the request header carrying the Unix timestamp.
	// Defaults to DefaultTimestampHeader ("X-Timestamp").
	TimestampHeader string
	// ReplayWindow is how far in the past or future a timestamp may be.
	// Defaults to DefaultReplayWindow (5 minutes).
	ReplayWindow time.Duration
	// OnError is called when verification fails. Defaults to a 401 JSON response.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

// Middleware returns an HTTP middleware that verifies the HMAC-SHA256 signature
// on inbound requests (e.g. webhooks from a third-party service).
//
// The request body is read, verified, and then restored so that downstream
// handlers can read it again.
func Middleware(secret []byte, opts ...VerifyOptions) func(http.Handler) http.Handler {
	cfg := VerifyOptions{
		Header:          DefaultHeader,
		TimestampHeader: DefaultTimestampHeader,
		ReplayWindow:    DefaultReplayWindow,
		OnError:         defaultOnError,
	}
	if len(opts) > 0 {
		o := opts[0]
		if o.Header != "" {
			cfg.Header = o.Header
		}
		if o.TimestampHeader != "" {
			cfg.TimestampHeader = o.TimestampHeader
		}
		if o.ReplayWindow > 0 {
			cfg.ReplayWindow = o.ReplayWindow
		}
		if o.OnError != nil {
			cfg.OnError = o.OnError
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sig := r.Header.Get(cfg.Header)
			tsStr := r.Header.Get(cfg.TimestampHeader)
			if sig == "" || tsStr == "" {
				cfg.OnError(w, r, ErrMissingHeader)
				return
			}

			ts, err := strconv.ParseInt(strings.TrimSpace(tsStr), 10, 64)
			if err != nil {
				cfg.OnError(w, r, ErrInvalidSignature)
				return
			}

			// Replay check.
			age := time.Since(time.Unix(ts, 0)).Abs()
			if age > cfg.ReplayWindow {
				cfg.OnError(w, r, ErrReplayDetected)
				return
			}

			// Read and restore the body.
			body, err := io.ReadAll(r.Body)
			if err != nil {
				cfg.OnError(w, r, fmt.Errorf("reqsign: failed to read body: %w", err))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			if !Verify(secret, body, time.Unix(ts, 0), sig) {
				cfg.OnError(w, r, ErrInvalidSignature)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─── SigningTransport (outbound signing) ──────────────────────────────────────

// SigningTransport is an http.RoundTripper that automatically signs every
// outbound request with HMAC-SHA256 before sending it.
//
//	client := &http.Client{Transport: reqsign.NewSigningTransport(secret, nil)}
type SigningTransport struct {
	Secret          []byte
	Transport       http.RoundTripper
	Header          string
	TimestampHeader string
}

// NewSigningTransport creates a SigningTransport with the given secret.
// base may be nil, in which case http.DefaultTransport is used.
func NewSigningTransport(secret []byte, base http.RoundTripper) *SigningTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &SigningTransport{
		Secret:          secret,
		Transport:       base,
		Header:          DefaultHeader,
		TimestampHeader: DefaultTimestampHeader,
	}
}

// RoundTrip signs the request and delegates to the underlying transport.
func (t *SigningTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Clone the request so we don't mutate the original.
	r = r.Clone(r.Context())

	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("reqsign: failed to read request body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	now := time.Now()
	sig := Sign(t.Secret, body, now)
	r.Header.Set(t.TimestampHeader, strconv.FormatInt(now.Unix(), 10))
	r.Header.Set(t.Header, sig)

	return t.Transport.RoundTrip(r)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func buildPayload(ts int64, body []byte) []byte {
	prefix := []byte(strconv.FormatInt(ts, 10) + "\n")
	payload := make([]byte, len(prefix)+len(body))
	copy(payload, prefix)
	copy(payload[len(prefix):], body)
	return payload
}

func defaultOnError(w http.ResponseWriter, _ *http.Request, err error) {
	status := http.StatusUnauthorized
	msg := `{"error":"invalid request signature"}`
	if errors.Is(err, ErrReplayDetected) {
		status = http.StatusUnauthorized
		msg = `{"error":"request timestamp outside allowed window"}`
	} else if errors.Is(err, ErrMissingHeader) {
		msg = `{"error":"missing signature headers"}`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
