package ecc_test

import (
	"fmt"

	"github.com/shovon/go-eccfrog512ck2/ecc"
)

func Example_derivePublicKey() {
	// Generate a random private key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		return
	}

	// Derive the public key from the private key
	pubKey, err := privKey.DerivePublicKey()
	if err != nil {
		fmt.Printf("Error deriving public key: %v\n", err)
		return
	}

	// Get the coordinates of the public key point
	x, y, ok := pubKey.CoordinateIfNotInfinity()
	if !ok {
		fmt.Println("Public key is point at infinity")
		return
	}

	fmt.Printf("Private Key: %x\n", privKey.GetKey().Bytes())
	fmt.Printf("Public Key X: %x\n", x.Bytes())
	fmt.Printf("Public Key Y: %x\n", y.Bytes())
}

func Example_generatePrivateKey() {
	// Generate a random private key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		return
	}

	// Display the private key in hexadecimal format
	fmt.Printf("Generated Private Key: %x\n", privKey.GetKey().Bytes())

	// You can also marshal the private key in SEC1 format
	// with or without the version byte
	withVersion := privKey.MarshalSEC1(true)
	withoutVersion := privKey.MarshalSEC1(false)

	fmt.Printf("Private Key (SEC1 with version): %x\n", withVersion)
	fmt.Printf("Private Key (SEC1 without version): %x\n", withoutVersion)
}
