package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateToken returns a cryptographically secure random token of the given
// byte length, encoded as a base64url string (no padding).
// A length of 32 bytes provides 256 bits of entropy — suitable for session
// tokens, CSRF tokens, and API keys.
func GenerateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto: failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MustGenerateToken is like GenerateToken but panics on error.
// Only use in initialization code or tests where panicking is acceptable.
func MustGenerateToken(length int) string {
	t, err := GenerateToken(length)
	if err != nil {
		panic(err)
	}
	return t
}
