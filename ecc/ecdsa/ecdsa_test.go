package ecdsa_test

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/ecdsa"
)

func TestSignAndVerify(t *testing.T) {
	// Generate a private key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	pubKey, err := privKey.DerivePublicKey()
	if err != nil {
		t.Error(err)
	}

	// Message to sign
	message := []byte("test message")

	signer := ecdsa.NewSign(sha256.New, privKey)

	// Sign the message
	r, s, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	verification := ecdsa.NewVerification(sha256.New, pubKey)
	ok, err := verification.Verify([2]*big.Int{r, s}, message)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Fail()
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	// Generate keys
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := privKey.DerivePublicKey()
	if err != nil {
		t.Error(err)
	}

	// Original message and tampered message
	message := []byte("original message")
	tamperedMessage := []byte("tampered message")

	// Sign original message
	signer := ecdsa.NewSign(sha256.New, privKey)
	r, s, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify with tampered message
	verification := ecdsa.NewVerification(sha256.New, pubKey)
	valid, err := verification.Verify([2]*big.Int{r, s}, tamperedMessage)
	if err != nil {
		t.Error(err)
	}
	if valid {
		t.Error("Signature verification should fail for tampered message")
	}
}

func TestSignWithDifferentKeys(t *testing.T) {
	// Generate two different key pairs
	privKey1, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate first private key: %v", err)
	}
	privKey2, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate first private key: %v", err)
	}
	pubKey1, err := privKey1.DerivePublicKey()
	if err != nil {

	}

	message := []byte("test message")

	// Sign with first private key
	signer1 := ecdsa.NewSign(sha256.New, privKey1)
	r1, s1, err := signer1.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Generate second signature with different key
	signer2 := ecdsa.NewSign(sha256.New, privKey2)
	r2, s2, err := signer2.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify signatures
	verification := ecdsa.NewVerification(sha256.New, pubKey1)
	valid, err := verification.Verify([2]*big.Int{r1, s1}, message)
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("Signature verification failed for valid signature")
	}

	// Verify signature2 against pubKey1 (should fail)
	valid, err = verification.Verify([2]*big.Int{r2, s2}, message)
	if err != nil {
		t.Error(err)
	}
	if valid {
		t.Error("Signature verification should fail for signature from different key")
	}
}
