// Package jwt provides JWT creation, validation, and revocation for the
// api-security-sdk. It supports HMAC (HS256/384/512), RSA (RS256/512), and
// ECDSA (ES256/384/512) signing algorithms.
//
// Quick start:
//
//	svc := jwt.New(jwt.WithHMAC([]byte("at-least-32-bytes-secret")))
//
//	token, err := svc.Sign(jwt.Claims{Subject: "user123"})
//
//	claims, err := svc.Verify(token)
package jwt

import (
	"errors"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// Sentinel errors returned by Service methods.
var (
	ErrInvalidToken         = errors.New("jwt: invalid token")
	ErrExpiredToken         = errors.New("jwt: token has expired")
	ErrInvalidSigningMethod = errors.New("jwt: unexpected signing method")
	ErrTokenRevoked         = errors.New("jwt: token has been revoked")
	ErrNoBlacklist          = errors.New("jwt: no blacklist configured; use WithBlacklist")
	ErrMissingAlgorithm     = errors.New("jwt: no signing algorithm configured; use WithHMAC, WithRSA, or WithECDSA")
)

// Service handles JWT signing, verification, and revocation.
type Service struct {
	opts options
}

// New creates a JWT Service. At least one algorithm option (WithHMAC, WithRSA,
// WithECDSA, or WithJWKS) must be provided before calling Sign or Verify.
func New(opts ...Option) *Service {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return &Service{opts: o}
}

// Sign creates a signed JWT string for the given claims.
func (s *Service) Sign(claims Claims) (string, error) {
	if s.opts.signingMethod == nil {
		return "", ErrMissingAlgorithm
	}
	now := time.Now()
	c := &standardClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   claims.Subject,
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(s.opts.expiry)),
			NotBefore: gojwt.NewNumericDate(now),
		},
		Custom: claims.Custom,
	}
	if s.opts.issuer != "" {
		c.Issuer = s.opts.issuer
	}
	if len(claims.Audience) > 0 {
		c.Audience = gojwt.ClaimStrings(claims.Audience)
	}
	return gojwt.NewWithClaims(s.opts.signingMethod, c).SignedString(s.opts.signingKey)
}

// Verify parses and validates a JWT string, returning its claims on success.
// Returns an error if the token is malformed, expired, signed with the wrong
// algorithm, or present in the revocation blacklist.
//
// When WithJWKS was used, the external keyfunc is called to resolve the key.
// Otherwise, the statically configured verifyKey is used.
func (s *Service) Verify(tokenString string) (*Claims, error) {
	if s.opts.keyFunc == nil && s.opts.signingMethod == nil {
		return nil, ErrMissingAlgorithm
	}

	keyfunc := s.opts.keyFunc
	if keyfunc == nil {
		keyfunc = func(t *gojwt.Token) (any, error) {
			if t.Method.Alg() != s.opts.signingMethod.Alg() {
				return nil, ErrInvalidSigningMethod
			}
			return s.opts.verifyKey, nil
		}
	}

	c := &standardClaims{}
	token, err := gojwt.ParseWithClaims(tokenString, c, keyfunc)
	if err != nil {
		return nil, mapJWTError(err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if s.opts.blacklist != nil {
		revoked, bErr := s.opts.blacklist.IsRevoked(tokenString)
		if bErr != nil || revoked {
			return nil, ErrTokenRevoked
		}
	}

	cl := &Claims{
		Subject: c.Subject,
		Custom:  c.Custom,
	}
	if len(c.Audience) > 0 {
		cl.Audience = []string(c.Audience)
	}
	if c.ExpiresAt != nil {
		cl.ExpiresAt = c.ExpiresAt.Time
	}
	if c.IssuedAt != nil {
		cl.IssuedAt = c.IssuedAt.Time
	}
	return cl, nil
}

// Refresh validates an existing token and issues a new one with a fresh expiry
// window. If a blacklist is configured the old token is revoked automatically.
func (s *Service) Refresh(tokenString string) (string, error) {
	claims, err := s.Verify(tokenString)
	if err != nil {
		return "", err
	}
	if s.opts.blacklist != nil {
		_ = s.opts.blacklist.Revoke(tokenString)
	}
	return s.Sign(*claims)
}

// Revoke adds a token to the blacklist so subsequent Verify calls reject it.
// Returns ErrNoBlacklist if no blacklist was configured.
func (s *Service) Revoke(tokenString string) error {
	if s.opts.blacklist == nil {
		return ErrNoBlacklist
	}
	return s.opts.blacklist.Revoke(tokenString)
}

func mapJWTError(err error) error {
	switch {
	case errors.Is(err, gojwt.ErrTokenExpired):
		return ErrExpiredToken
	case errors.Is(err, gojwt.ErrSignatureInvalid),
		errors.Is(err, gojwt.ErrTokenMalformed),
		errors.Is(err, gojwt.ErrTokenNotValidYet),
		errors.Is(err, gojwt.ErrTokenUnverifiable):
		return ErrInvalidToken
	default:
		return err
	}
}
