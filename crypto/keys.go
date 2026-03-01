package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateRSAKeyPair generates an RSA key pair of the given bit size.
// Use 2048 as the minimum; prefer 4096 for long-lived keys.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: RSA key generation failed: %w", err)
	}
	return priv, &priv.PublicKey, nil
}

// GenerateECDSAKeyPair generates an ECDSA key pair using the given curve.
// Recommended: elliptic.P256() (ES256) or elliptic.P521() (ES512).
func GenerateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: ECDSA key generation failed: %w", err)
	}
	return priv, &priv.PublicKey, nil
}

// RSAPrivateKeyToPEM encodes an RSA private key to PKCS8 PEM format.
func RSAPrivateKeyToPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// RSAPublicKeyToPEM encodes an RSA public key to PKIX PEM format.
func RSAPublicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ECDSAPrivateKeyToPEM encodes an ECDSA private key to PKCS8 PEM format.
func ECDSAPrivateKeyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ECDSAPublicKeyToPEM encodes an ECDSA public key to PKIX PEM format.
func ECDSAPublicKeyToPEM(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParseRSAPrivateKeyPEM parses a PEM-encoded PKCS8 RSA private key.
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto: failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: PEM block does not contain an RSA private key")
	}
	return rsaKey, nil
}

// ParseRSAPublicKeyPEM parses a PEM-encoded PKIX RSA public key.
func ParseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto: failed to decode PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("crypto: PEM block does not contain an RSA public key")
	}
	return rsaKey, nil
}

// ParseECDSAPrivateKeyPEM parses a PEM-encoded PKCS8 ECDSA private key.
func ParseECDSAPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto: failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: PEM block does not contain an ECDSA private key")
	}
	return ecKey, nil
}

// ParseECDSAPublicKeyPEM parses a PEM-encoded PKIX ECDSA public key.
func ParseECDSAPublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto: failed to decode PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("crypto: PEM block does not contain an ECDSA public key")
	}
	return ecKey, nil
}
