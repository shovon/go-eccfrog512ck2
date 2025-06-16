package ecdh_test

import (
	"testing"

	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/ecdh"
)

func TestDeriveSharedSecret(t *testing.T) {
	// Generate a private key
	privateKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	ecdhPrivateKey := ecdh.ECDHPrivateKey(privateKey)

	// Get the corresponding public key
	publicKey, err := privateKey.DerivePublicKey()
	if err != nil {
		t.Error(err)
	}

	// Test successful key derivation
	sharedSecret, err := ecdhPrivateKey.DeriveSharedSecret(publicKey)
	if err != nil {
		t.Error(err)
	}
	if len(sharedSecret) == 0 {
		t.Error("DeriveSharedSecret returned empty shared secret")
	}

	// Test with a different public key
	otherPrivateKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate other private key: %v", err)
	}
	otherPublicKey, err := otherPrivateKey.DerivePublicKey()
	if err != nil {
		t.Error("The other public key failed to be generated")
	}
	otherSharedSecret, err := ecdhPrivateKey.DeriveSharedSecret(otherPublicKey)
	if err != nil {
		t.Error(err)
	}
	if len(otherSharedSecret) == 0 {
		t.Error("DeriveSharedSecret returned empty shared secret with different public key")
	}
}
