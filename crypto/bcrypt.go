package crypto

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// DefaultBcryptCost is the default bcrypt work factor (10). Increase for
// higher security at the cost of more CPU time per hash.
// Benchmark on your hardware: a hash should take roughly 100–300 ms.
const DefaultBcryptCost = bcrypt.DefaultCost

// HashPasswordBcrypt hashes password using bcrypt with the given cost factor.
// Pass 0 to use DefaultBcryptCost.
//
// Prefer HashPassword (Argon2id) for new systems — bcrypt is provided for
// compatibility with existing databases that already store bcrypt hashes.
func HashPasswordBcrypt(password string, cost int) (string, error) {
	if cost <= 0 {
		cost = DefaultBcryptCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("crypto: bcrypt hash failed: %w", err)
	}
	return string(hash), nil
}

// VerifyPasswordBcrypt checks whether password matches the stored bcrypt hash.
// Returns (false, nil) on mismatch — only returns an error on unexpected failure.
func VerifyPasswordBcrypt(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == nil {
		return true, nil
	}
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	return false, fmt.Errorf("crypto: bcrypt verify failed: %w", err)
}

// BcryptCost returns the cost factor embedded in an existing bcrypt hash.
// Useful when deciding whether to rehash a stored hash at a higher cost.
func BcryptCost(hash string) (int, error) {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return 0, fmt.Errorf("crypto: failed to read bcrypt cost: %w", err)
	}
	return cost, nil
}
