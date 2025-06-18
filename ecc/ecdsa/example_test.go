package ecdsa_test

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/ecdsa"
)

func Example() {
	// Generate a private key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return
	}

	// Derive the public key
	pubKey, err := privKey.DerivePublicKey()
	if err != nil {
		fmt.Println("Failed to derive public key:", err)
		return
	}

	// The message to sign
	message := []byte("hello, world!")

	// Create a signer
	signer := ecdsa.NewSign(sha256.New, privKey)

	// Sign the message
	r, s, err := signer.Sign(message)
	if err != nil {
		fmt.Println("Failed to sign message:", err)
		return
	}

	// Create a verifier
	verifier := ecdsa.NewVerification(sha256.New, pubKey)

	// Verify the signature
	ok, err := verifier.Verify([2]*big.Int{r, s}, message)
	if err != nil {
		fmt.Println("Verification error:", err)
		return
	}

	fmt.Println("Signature valid?", ok)
	// Output:
	// Signature valid? true
}
