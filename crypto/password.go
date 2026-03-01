// Package crypto provides cryptographic utilities for secure applications.
// It includes Argon2id password hashing, secure random token generation,
// and RSA/ECDSA key generation helpers.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordConfig holds the Argon2id tuning parameters.
type PasswordConfig struct {
	Memory      uint32 // KiB of memory (default: 64 MiB)
	Iterations  uint32 // Number of passes (default: 3)
	Parallelism uint8  // Degree of parallelism (default: 2)
	SaltLength  uint32 // Salt length in bytes (default: 16)
	KeyLength   uint32 // Derived key length in bytes (default: 32)
}

// DefaultPasswordConfig returns OWASP-recommended Argon2id parameters.
func DefaultPasswordConfig() PasswordConfig {
	return PasswordConfig{
		Memory:      64 * 1024, // 64 MiB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// HashPassword hashes a plaintext password using Argon2id with the default
// configuration. The returned string is PHC-formatted and safe to store
// directly in a database.
func HashPassword(password string) (string, error) {
	return HashPasswordWithConfig(password, DefaultPasswordConfig())
}

// HashPasswordWithConfig hashes a password using the given Argon2id configuration.
func HashPasswordWithConfig(password string, cfg PasswordConfig) (string, error) {
	salt := make([]byte, cfg.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto: failed to generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, cfg.Iterations, cfg.Memory, cfg.Parallelism, cfg.KeyLength)
	return encodeHash(hash, salt, cfg), nil
}

// VerifyPassword checks whether password matches the encoded Argon2id hash.
// Uses constant-time comparison to prevent timing attacks.
func VerifyPassword(password, encoded string) (bool, error) {
	cfg, salt, hash, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	candidate := argon2.IDKey([]byte(password), salt, cfg.Iterations, cfg.Memory, cfg.Parallelism, cfg.KeyLength)
	return subtle.ConstantTimeCompare(hash, candidate) == 1, nil
}

// encodeHash formats parameters and hashes as a PHC string.
func encodeHash(hash, salt []byte, cfg PasswordConfig) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		cfg.Memory,
		cfg.Iterations,
		cfg.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

var errInvalidHash = errors.New("crypto: invalid argon2id hash format")

// decodeHash parses a PHC-formatted Argon2id string.
func decodeHash(encoded string) (cfg PasswordConfig, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return cfg, nil, nil, errInvalidHash
	}
	if parts[1] != "argon2id" {
		return cfg, nil, nil, errInvalidHash
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return cfg, nil, nil, errInvalidHash
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &cfg.Memory, &cfg.Iterations, &cfg.Parallelism); err != nil {
		return cfg, nil, nil, errInvalidHash
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return cfg, nil, nil, errInvalidHash
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return cfg, nil, nil, errInvalidHash
	}
	cfg.SaltLength = uint32(len(salt))
	cfg.KeyLength = uint32(len(hash))
	return cfg, salt, hash, nil
}
