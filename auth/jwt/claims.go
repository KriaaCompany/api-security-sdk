package jwt

import (
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// Claims represents the payload of a JWT token.
type Claims struct {
	// Subject identifies the principal that is the subject of the token (e.g. user ID).
	Subject string

	// Audience identifies the recipients that the token is intended for.
	Audience []string

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time

	// IssuedAt is when the token was issued.
	IssuedAt time.Time

	// Custom holds application-specific claims.
	Custom map[string]any
}

// standardClaims is the internal representation used with the JWT library.
type standardClaims struct {
	gojwt.RegisteredClaims
	Custom map[string]any `json:"cst,omitempty"`
}
