// Package otp implements Time-based One-Time Passwords (TOTP) per RFC 6238
// using only the Go standard library. It is compatible with Google Authenticator,
// Authy, 1Password, and any other RFC 6238-compliant authenticator app.
//
// Quick start:
//
//	// On account setup — generate a secret and show the provisioning URI as a QR code.
//	secret, _ := otp.NewSecret()
//	uri := otp.ProvisioningURI("alice@example.com", "MyApp", secret)
//	// Render uri as a QR code using any QR library.
//
//	// On login — verify the code from the user's authenticator app.
//	ok, err := otp.Verify(secret, userSuppliedCode)
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates SHA-1 for TOTP
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultDigits is the standard OTP code length.
	DefaultDigits = 6
	// DefaultPeriod is the standard TOTP time step in seconds.
	DefaultPeriod = 30
	// DefaultSkew is the number of adjacent time steps checked on either side
	// of the current step to account for clock drift.
	DefaultSkew = 1
	// SecretBytes is the recommended secret length (20 bytes → 160-bit secret).
	SecretBytes = 20
)

// ErrInvalidCode is returned when the supplied code does not match.
var ErrInvalidCode = errors.New("otp: invalid code")

// ─── Secret management ────────────────────────────────────────────────────────

// NewSecret generates a cryptographically secure, base32-encoded TOTP secret.
// Store this value (encrypted at rest) per user. Show it to the user during
// setup via ProvisioningURI.
func NewSecret() (string, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("otp: failed to generate secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ─── Code generation ─────────────────────────────────────────────────────────

// GenerateAt returns the TOTP code for the given secret at time t, using the
// default 30-second period and 6-digit output.
func GenerateAt(secret string, t time.Time) (string, error) {
	return generateHOTP(secret, counterFor(t, DefaultPeriod), DefaultDigits)
}

// Generate returns the current TOTP code using the system clock.
func Generate(secret string) (string, error) {
	return GenerateAt(secret, time.Now())
}

// ─── Verification ─────────────────────────────────────────────────────────────

// VerifyOptions configures TOTP verification behaviour.
type VerifyOptions struct {
	// Digits is the expected code length (default: 6).
	Digits int
	// Period is the time step in seconds (default: 30).
	Period uint
	// Skew is the number of time steps to check on either side of the current
	// step (default: 1, meaning ±30 seconds tolerance with a 30-second period).
	Skew uint
}

// Verify checks whether code is a valid TOTP for secret at the current time,
// allowing for the default clock drift tolerance (±1 step).
func Verify(secret, code string) (bool, error) {
	return VerifyWithOptions(secret, code, VerifyOptions{})
}

// VerifyWithOptions is like Verify but accepts custom parameters.
func VerifyWithOptions(secret, code string, opts VerifyOptions) (bool, error) {
	digits := opts.Digits
	if digits == 0 {
		digits = DefaultDigits
	}
	period := opts.Period
	if period == 0 {
		period = DefaultPeriod
	}
	skew := opts.Skew
	if skew == 0 {
		skew = DefaultSkew
	}

	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false, ErrInvalidCode
	}

	now := time.Now()
	counter := counterFor(now, period)

	for i := -int64(skew); i <= int64(skew); i++ {
		candidate, err := generateHOTP(secret, uint64(int64(counter)+i), digits)
		if err != nil {
			return false, err
		}
		if hmac.Equal([]byte(candidate), []byte(code)) {
			return true, nil
		}
	}
	return false, ErrInvalidCode
}

// ─── Provisioning URI (for QR codes) ─────────────────────────────────────────

// ProvisioningURI returns an otpauth:// URI that encodes the TOTP parameters.
// Most authenticator apps accept this URI as a QR code payload.
//
//	uri := otp.ProvisioningURI("alice@example.com", "MyApp", secret)
//	// Pass uri to a QR code library (e.g. github.com/skip2/go-qrcode).
func ProvisioningURI(account, issuer, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(DefaultDigits))
	v.Set("period", fmt.Sprint(DefaultPeriod))

	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// ─── Backup codes ─────────────────────────────────────────────────────────────

// GenerateBackupCodes returns n single-use backup codes. Each code is a
// random 10-character alphanumeric string. Store the SHA-256 hashes of the
// returned codes (use crypto.HashPassword) and cross them off as they are used.
func GenerateBackupCodes(n int) ([]string, error) {
	const chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" // Crockford base32 — unambiguous
	codes := make([]string, n)
	buf := make([]byte, 10)
	for i := range codes {
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("otp: backup code generation failed: %w", err)
		}
		b := make([]byte, 10)
		for j, c := range buf {
			b[j] = chars[int(c)%len(chars)]
		}
		// Format as XXXXX-XXXXX for readability.
		codes[i] = string(b[:5]) + "-" + string(b[5:])
	}
	return codes, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func counterFor(t time.Time, period uint) uint64 {
	return uint64(t.Unix()) / uint64(period)
}

func generateHOTP(secret string, counter uint64, digits int) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}

	// HOTP: HMAC-SHA1 of the 8-byte big-endian counter.
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, key) //nolint:gosec // RFC 4226 mandates SHA-1
	_, _ = mac.Write(msg)
	h := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.4).
	offset := h[len(h)-1] & 0x0f
	code := (uint32(h[offset]&0x7f)<<24 |
		uint32(h[offset+1])<<16 |
		uint32(h[offset+2])<<8 |
		uint32(h[offset+3])) % uint32(math.Pow10(digits))

	return fmt.Sprintf("%0*d", digits, code), nil
}

func decodeSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(strings.ToUpper(secret))
	// Pad to a multiple of 8 if necessary.
	if pad := len(secret) % 8; pad != 0 {
		secret += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("otp: invalid base32 secret: %w", err)
	}
	return key, nil
}
