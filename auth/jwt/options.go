package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

const defaultExpiry = time.Hour

type options struct {
	signingMethod gojwt.SigningMethod
	signingKey    any
	verifyKey     any
	expiry        time.Duration
	issuer        string
	blacklist     Blacklist
}

func defaultOptions() options {
	return options{expiry: defaultExpiry}
}

// Option configures the JWT Service.
type Option func(*options)

// WithHMAC configures HMAC-SHA256 (HS256) signing with the given secret.
// The secret must be at least 32 bytes to provide adequate security.
func WithHMAC(secret []byte) Option {
	return func(o *options) {
		o.signingMethod = gojwt.SigningMethodHS256
		o.signingKey = secret
		o.verifyKey = secret
	}
}

// WithHMAC384 configures HMAC-SHA384 (HS384) signing.
func WithHMAC384(secret []byte) Option {
	return func(o *options) {
		o.signingMethod = gojwt.SigningMethodHS384
		o.signingKey = secret
		o.verifyKey = secret
	}
}

// WithHMAC512 configures HMAC-SHA512 (HS512) signing.
func WithHMAC512(secret []byte) Option {
	return func(o *options) {
		o.signingMethod = gojwt.SigningMethodHS512
		o.signingKey = secret
		o.verifyKey = secret
	}
}

// WithRSA configures RSA-SHA256 (RS256) signing.
// Use a minimum key size of 2048 bits.
func WithRSA(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) Option {
	return func(o *options) {
		o.signingMethod = gojwt.SigningMethodRS256
		o.signingKey = privateKey
		o.verifyKey = publicKey
	}
}

// WithRSA512 configures RSA-SHA512 (RS512) signing.
func WithRSA512(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) Option {
	return func(o *options) {
		o.signingMethod = gojwt.SigningMethodRS512
		o.signingKey = privateKey
		o.verifyKey = publicKey
	}
}

// WithECDSA configures ECDSA signing. The algorithm is auto-detected from the
// key's curve: P-256 → ES256, P-384 → ES384, P-521 → ES512.
func WithECDSA(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) Option {
	return func(o *options) {
		switch privateKey.Curve {
		case elliptic.P384():
			o.signingMethod = gojwt.SigningMethodES384
		case elliptic.P521():
			o.signingMethod = gojwt.SigningMethodES512
		default: // P-256
			o.signingMethod = gojwt.SigningMethodES256
		}
		o.signingKey = privateKey
		o.verifyKey = publicKey
	}
}

// WithExpiry sets the token lifetime (default: 1 hour).
func WithExpiry(d time.Duration) Option {
	return func(o *options) { o.expiry = d }
}

// WithIssuer sets the "iss" claim on all issued tokens.
func WithIssuer(issuer string) Option {
	return func(o *options) { o.issuer = issuer }
}

// WithBlacklist attaches a token revocation store to the service.
// Revoked tokens are rejected during Verify.
func WithBlacklist(bl Blacklist) Option {
	return func(o *options) { o.blacklist = bl }
}
