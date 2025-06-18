package ecdh_test

import (
	"fmt"
	"log"

	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/ecdh"
)

func ExampleDeriveSharedSecret() {
	// Generate Alice's private key
	alicePriv, err := ecc.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate Alice's private key: %v", err)
	}
	aliceECDH := ecdh.ECDHPrivateKey(alicePriv)

	// Generate Bob's private key
	bobPriv, err := ecc.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate Bob's private key: %v", err)
	}
	bobECDH := ecdh.ECDHPrivateKey(bobPriv)

	// Derive public keys
	alicePub, err := alicePriv.DerivePublicKey()
	if err != nil {
		log.Fatalf("Failed to derive Alice's public key: %v", err)
	}
	bobPub, err := bobPriv.DerivePublicKey()
	if err != nil {
		log.Fatalf("Failed to derive Bob's public key: %v", err)
	}

	// Each party derives the shared secret using the other's public key
	aliceShared, err := aliceECDH.DeriveSharedSecret(bobPub)
	if err != nil {
		log.Fatalf("Alice failed to derive shared secret: %v", err)
	}
	bobShared, err := bobECDH.DeriveSharedSecret(alicePub)
	if err != nil {
		log.Fatalf("Bob failed to derive shared secret: %v", err)
	}

	// The shared secrets should be equal
	fmt.Printf("Alice's shared secret: %x\n", aliceShared)
	fmt.Printf("Bob's shared secret:   %x\n", bobShared)
	if string(aliceShared) == string(bobShared) {
		fmt.Println("Shared secrets match!")
	} else {
		fmt.Println("Shared secrets do NOT match!")
	}
	// Output:
	// Shared secrets match!
}
