// Package passwdpolicy enforces password strength and complexity requirements
// before a password is hashed and stored. Use it at the point of password
// creation and change, then pass the validated password to crypto.HashPassword.
//
// Quick start:
//
//	policy := passwdpolicy.OWASP()
//	if violations := policy.Validate(password); len(violations) > 0 {
//	    // return violations to the user
//	}
//
// Custom policy:
//
//	policy := passwdpolicy.Policy{
//	    MinLength:      12,
//	    RequireUpper:   true,
//	    RequireDigit:   true,
//	    RequireSpecial: true,
//	    MinEntropy:     40,
//	}
package passwdpolicy

import (
	"fmt"
	"math"
	"strings"
	"unicode"
)

// Violation describes a single password policy rule that was not satisfied.
type Violation struct {
	// Rule is a machine-readable identifier for the failed rule.
	Rule string
	// Message is a human-readable description suitable for display to the user.
	Message string
}

func (v Violation) Error() string { return fmt.Sprintf("%s: %s", v.Rule, v.Message) }

// Policy defines the rules a password must satisfy.
type Policy struct {
	// MinLength is the minimum password length (default: 8).
	MinLength int
	// MaxLength is the maximum password length. 0 means no limit.
	// Setting a very low maximum (< 64) is not recommended.
	MaxLength int

	// RequireUpper requires at least one uppercase letter (A-Z).
	RequireUpper bool
	// RequireLower requires at least one lowercase letter (a-z).
	RequireLower bool
	// RequireDigit requires at least one decimal digit (0-9).
	RequireDigit bool
	// RequireSpecial requires at least one special/punctuation character.
	RequireSpecial bool

	// MinEntropy is the minimum estimated entropy in bits.
	// Entropy is estimated from the password character class diversity and length.
	// A value of 0 disables the entropy check.
	// 28 bits ≈ weak, 36 bits ≈ reasonable, 60 bits ≈ strong.
	MinEntropy float64

	// DisallowCommon rejects passwords found in the built-in list of the most
	// commonly used passwords (top ~100).
	DisallowCommon bool

	// Blocklist is an additional set of exact strings to reject (case-insensitive).
	// Use this to block company names, product names, or context-specific terms.
	Blocklist []string
}

// OWASP returns a policy aligned with the OWASP Authentication Cheat Sheet
// recommendations: minimum 8 characters, no maximum, no mandatory complexity
// rules (rely on length and entropy instead), common password rejection.
//
// Reference: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
func OWASP() Policy {
	return Policy{
		MinLength:      8,
		MinEntropy:     28,
		DisallowCommon: true,
	}
}

// Strict returns a high-security policy suitable for privileged accounts,
// service credentials, and admin panels.
func Strict() Policy {
	return Policy{
		MinLength:      12,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		MinEntropy:     50,
		DisallowCommon: true,
	}
}

// Validate checks password against all policy rules and returns a list of
// violations. An empty slice means the password is acceptable.
func (p Policy) Validate(password string) []Violation {
	p.applyDefaults()
	var violations []Violation

	add := func(rule, format string, args ...any) {
		violations = append(violations, Violation{Rule: rule, Message: fmt.Sprintf(format, args...)})
	}

	// Length checks.
	runes := []rune(password)
	length := len(runes)

	if length < p.MinLength {
		add("min_length", "must be at least %d characters long", p.MinLength)
	}
	if p.MaxLength > 0 && length > p.MaxLength {
		add("max_length", "must be at most %d characters long", p.MaxLength)
	}

	// Character class checks.
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range runes {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	if p.RequireUpper && !hasUpper {
		add("require_upper", "must contain at least one uppercase letter")
	}
	if p.RequireLower && !hasLower {
		add("require_lower", "must contain at least one lowercase letter")
	}
	if p.RequireDigit && !hasDigit {
		add("require_digit", "must contain at least one digit")
	}
	if p.RequireSpecial && !hasSpecial {
		add("require_special", "must contain at least one special character")
	}

	// Entropy check.
	if p.MinEntropy > 0 {
		entropy := estimateEntropy(password, hasUpper, hasLower, hasDigit, hasSpecial)
		if entropy < p.MinEntropy {
			add("min_entropy", "password is too weak (estimated %.0f bits, need %.0f)", entropy, p.MinEntropy)
		}
	}

	// Common password check.
	lower := strings.ToLower(password)
	if p.DisallowCommon && commonPasswords[lower] {
		add("common_password", "this password is too common; choose a more unique password")
	}

	// Custom blocklist.
	for _, blocked := range p.Blocklist {
		if strings.EqualFold(password, blocked) {
			add("blocklist", "this password is not allowed")
			break
		}
	}

	return violations
}

// IsValid reports whether the password satisfies all policy rules.
func (p Policy) IsValid(password string) bool {
	return len(p.Validate(password)) == 0
}

func (p *Policy) applyDefaults() {
	if p.MinLength == 0 {
		p.MinLength = 8
	}
}

// ─── Entropy estimation ───────────────────────────────────────────────────────

// estimateEntropy computes Shannon entropy based on the alphabet size implied
// by the character classes present in the password:
//
//	entropy = length × log2(poolSize)
func estimateEntropy(password string, hasUpper, hasLower, hasDigit, hasSpecial bool) float64 {
	pool := 0
	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasSpecial {
		pool += 32 // approximate number of common special characters
	}
	if pool == 0 {
		return 0
	}
	return float64(len([]rune(password))) * math.Log2(float64(pool))
}

// ─── Common password list ─────────────────────────────────────────────────────

// commonPasswords is a set of the most frequently used passwords drawn from
// public breach datasets. This is a representative sample; for production use
// consider integrating with the HaveIBeenPwned k-Anonymity API.
var commonPasswords = map[string]bool{
	"password": true, "123456": true, "12345678": true, "qwerty": true,
	"abc123": true, "monkey": true, "1234567": true, "letmein": true,
	"trustno1": true, "dragon": true, "baseball": true, "iloveyou": true,
	"master": true, "sunshine": true, "ashley": true, "bailey": true,
	"passw0rd": true, "shadow": true, "123123": true, "654321": true,
	"superman": true, "qazwsx": true, "michael": true, "football": true,
	"password1": true, "password123": true, "welcome": true, "login": true,
	"admin": true, "admin123": true, "root": true, "toor": true,
	"pass": true, "test": true, "guest": true, "qwerty123": true,
	"1q2w3e": true, "1q2w3e4r": true, "1q2w3e4r5t": true,
	"zxcvbnm": true, "asdfghjkl": true, "qwertyuiop": true,
	"111111": true, "000000": true, "1111111": true, "11111111": true,
	"12345": true, "123456789": true, "1234567890": true,
	"princess": true, "starwars": true, "cheese": true, "summer": true,
	"flower": true, "playboy": true, "soccer": true, "hockey": true,
	"ranger": true, "batman": true, "hannah": true, "jessica": true,
	"george": true, "jordan": true, "harley": true, "ranger1": true,
	"daniel": true, "hunter": true, "hunter2": true, "buster": true,
	"robert": true, "thomas": true, "charlie": true, "andrew": true,
	"andrea": true, "joshua": true, "jonathan": true, "nicholas": true,
}

// Strength represents a qualitative password strength level.
type Strength int

const (
	StrengthVeryWeak Strength = iota
	StrengthWeak
	StrengthFair
	StrengthStrong
	StrengthVeryStrong
)

// String returns a human-readable strength label.
func (s Strength) String() string {
	switch s {
	case StrengthVeryWeak:
		return "very weak"
	case StrengthWeak:
		return "weak"
	case StrengthFair:
		return "fair"
	case StrengthStrong:
		return "strong"
	case StrengthVeryStrong:
		return "very strong"
	default:
		return "unknown"
	}
}

// EstimateStrength returns a qualitative strength rating for password.
// This is useful for driving a UI strength meter independently of policy validation.
func EstimateStrength(password string) Strength {
	runes := []rune(password)
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range runes {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	entropy := estimateEntropy(password, hasUpper, hasLower, hasDigit, hasSpecial)
	switch {
	case entropy < 28:
		return StrengthVeryWeak
	case entropy < 36:
		return StrengthWeak
	case entropy < 50:
		return StrengthFair
	case entropy < 65:
		return StrengthStrong
	default:
		return StrengthVeryStrong
	}
}
