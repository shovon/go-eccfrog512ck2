package ecc

import (
	"encoding/pem"
	"fmt"

	"github.com/shovon/go-eccfrog512ck2"
)

// MarshalPEM converts a private key to PEM format.
func (k PrivateKey) MarshalPEM() ([]byte, error) {
	// Convert private key to SEC1 format
	keyBytes := k.MarshalSEC1(true)

	// Create PEM block
	block := &pem.Block{
		Type:  "ECCFROG512CK2 PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Encode to PEM format
	return pem.EncodeToMemory(block), nil
}

// UnmarshalPEM parses a PEM-encoded private key.
func UnmarshalPEM(pemBytes []byte) (PrivateKey, error) {
	// Decode PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return PrivateKey{}, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "ECCFROG512CK2 PRIVATE KEY" {
		return PrivateKey{}, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	// Create private key from SEC1 format
	return ParsePrivateKeySEC1(block.Bytes)
}

// MarshalPublicPEM converts a public key to PEM format.
func MarshalPublicPEM(k eccfrog512ck2.CurvePoint) ([]byte, error) {
	// Convert public key to SEC1 format
	keyBytes := k.MarshalSEC1(false)

	// Create PEM block
	block := &pem.Block{
		Type:  "ECCFROG512CK2 PUBLIC KEY",
		Bytes: keyBytes,
	}

	// Encode to PEM format
	return pem.EncodeToMemory(block), nil
}

// UnmarshalPublicPEM parses a PEM-encoded public key.
func UnmarshalPublicPEM(pemBytes []byte) (eccfrog512ck2.CurvePoint, error) {
	// Decode PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return eccfrog512ck2.CurvePoint{}, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "ECCFROG512CK2 PUBLIC KEY" {
		return eccfrog512ck2.CurvePoint{}, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	// Create public key from SEC1 format
	return ParsePublicKeySEC1(block.Bytes)
}
