package ecc_test

import (
	"fmt"
	"math/big"

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

func Example_parsePrivateKeySEC1() {
	// Example 1: Parse a valid private key with version byte
	validKeyWithVersion := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	key1, err := ecc.ParsePrivateKeySEC1(validKeyWithVersion)
	if err != nil {
		fmt.Printf("Error parsing key with version: %v\n", err)
	} else {
		fmt.Printf("Successfully parsed key with version: %x\n", key1.GetKey().Bytes())
	}

	// Example 2: Parse a valid private key without version byte
	validKeyWithoutVersion := []byte{0x01, 0x02, 0x03, 0x04}
	key2, err := ecc.ParsePrivateKeySEC1(validKeyWithoutVersion)
	if err != nil {
		fmt.Printf("Error parsing key without version: %v\n", err)
	} else {
		fmt.Printf("Successfully parsed key without version: %x\n", key2.GetKey().Bytes())
	}

	// Example 3: Try to parse an invalid key (zero)
	zeroKey := []byte{0x00}
	_, err = ecc.ParsePrivateKeySEC1(zeroKey)
	if err != nil {
		fmt.Printf("Expected error for zero key: %v\n", err)
	}

	// Example 4: Try to parse an empty key
	emptyKey := []byte{}
	_, err = ecc.ParsePrivateKeySEC1(emptyKey)
	if err != nil {
		fmt.Printf("Expected error for empty key: %v\n", err)
	}

	// Example 5: Parse a key and then marshal it back to SEC1 format
	originalKey := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	parsedKey, err := ecc.ParsePrivateKeySEC1(originalKey)
	if err != nil {
		fmt.Printf("Error parsing key: %v\n", err)
		return
	}

	// Marshal back to SEC1 format with and without version
	marshaledWithVersion := parsedKey.MarshalSEC1(true)
	marshaledWithoutVersion := parsedKey.MarshalSEC1(false)

	fmt.Printf("Original key: %x\n", originalKey)
	fmt.Printf("Marshaled with version: %x\n", marshaledWithVersion)
	fmt.Printf("Marshaled without version: %x\n", marshaledWithoutVersion)
}

func Example_marshalPrivateKeySEC1() {
	// Example 1: Marshal a valid private key
	validKeyBytes := big.NewInt(0x1234567890).Bytes()
	validKey, err := ecc.ParsePrivateKeySEC1(validKeyBytes)
	if err != nil {
		fmt.Printf("Error creating test key: %v\n", err)
		return
	}

	// Marshal with version byte
	withVersion := validKey.MarshalSEC1(true)
	fmt.Printf("Key with version byte: %x\n", withVersion)

	// Marshal without version byte
	withoutVersion := validKey.MarshalSEC1(false)
	fmt.Printf("Key without version byte: %x\n", withoutVersion)

	// Example 2: Marshal a nil private key
	nilKey := ecc.PrivateKey{}
	nilResult := nilKey.MarshalSEC1(true)
	fmt.Printf("Nil key result: %v\n", nilResult)

	// Example 3: Marshal a key and then parse it back
	originalKeyBytes := big.NewInt(0x1234567890).Bytes()
	originalKey, err := ecc.ParsePrivateKeySEC1(originalKeyBytes)
	if err != nil {
		fmt.Printf("Error creating test key: %v\n", err)
		return
	}

	// Marshal with version
	marshaled := originalKey.MarshalSEC1(true)
	fmt.Printf("Marshaled key: %x\n", marshaled)

	// Parse it back
	parsedKey, err := ecc.ParsePrivateKeySEC1(marshaled)
	if err != nil {
		fmt.Printf("Error parsing marshaled key: %v\n", err)
		return
	}

	// Verify the round trip
	fmt.Printf("Original value: %x\n", originalKey.GetKey().Bytes())
	fmt.Printf("Parsed value: %x\n", parsedKey.GetKey().Bytes())
}

func Example_parsePublicKeySEC1() {
	// First, generate a key pair to get a valid public key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		return
	}

	pubKey, err := privKey.DerivePublicKey()
	if err != nil {
		fmt.Printf("Error deriving public key: %v\n", err)
		return
	}

	// Get the coordinates for creating SEC1 format
	x, y, ok := pubKey.CoordinateIfNotInfinity()
	if !ok {
		fmt.Println("Public key is point at infinity")
		return
	}

	// Example 1: Parse an uncompressed public key (0x04 || x || y)
	uncompressedKey := make([]byte, 129)
	uncompressedKey[0] = 0x04
	copy(uncompressedKey[1:65], x.Bytes())
	copy(uncompressedKey[65:129], y.Bytes())

	parsedUncompressed, err := ecc.ParsePublicKeySEC1(uncompressedKey)
	if err != nil {
		fmt.Printf("Error parsing uncompressed key: %v\n", err)
	} else {
		parsedX, parsedY, _ := parsedUncompressed.CoordinateIfNotInfinity()
		fmt.Printf("Successfully parsed uncompressed key:\n")
		fmt.Printf("  X: %x\n", parsedX.Bytes())
		fmt.Printf("  Y: %x\n", parsedY.Bytes())
	}

	// Example 2: Parse a compressed public key (0x02 || x for even y, 0x03 || x for odd y)
	compressedKey := make([]byte, 65)
	if y.Bit(0) == 0 {
		compressedKey[0] = 0x02 // even y
	} else {
		compressedKey[0] = 0x03 // odd y
	}
	copy(compressedKey[1:65], x.Bytes())

	parsedCompressed, err := ecc.ParsePublicKeySEC1(compressedKey)
	if err != nil {
		fmt.Printf("Error parsing compressed key: %v\n", err)
	} else {
		parsedX, parsedY, _ := parsedCompressed.CoordinateIfNotInfinity()
		fmt.Printf("Successfully parsed compressed key:\n")
		fmt.Printf("  X: %x\n", parsedX.Bytes())
		fmt.Printf("  Y: %x\n", parsedY.Bytes())
	}

	// Example 3: Try to parse an invalid format
	invalidKey := []byte{0x01} // Invalid format byte
	_, err = ecc.ParsePublicKeySEC1(invalidKey)
	if err != nil {
		fmt.Printf("Expected error for invalid format: %v\n", err)
	}

	// Example 4: Try to parse an empty key
	emptyKey := []byte{}
	_, err = ecc.ParsePublicKeySEC1(emptyKey)
	if err != nil {
		fmt.Printf("Expected error for empty key: %v\n", err)
	}
}

func Example_marshalPEM() {
	// Generate a random private key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		return
	}

	// Marshal the private key to PEM format
	pemBytes, err := privKey.MarshalPEM()
	if err != nil {
		fmt.Printf("Error marshalling to PEM: %v\n", err)
		return
	}

	// Print the PEM-encoded private key
	fmt.Printf("%s", pemBytes)
}

func Example_unmarshalPEM() {
	// Generate a random private key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		return
	}

	// Marshal the private key to PEM format
	pemBytes, err := privKey.MarshalPEM()
	if err != nil {
		fmt.Printf("Error marshalling to PEM: %v\n", err)
		return
	}

	// Unmarshal the PEM back to a private key
	parsedKey, err := ecc.UnmarshalPEM(pemBytes)
	if err != nil {
		fmt.Printf("Error unmarshalling PEM: %v\n", err)
		return
	}

	// Show that the original and parsed keys match
	fmt.Printf("Original key: %x\n", privKey.GetKey().Bytes())
	fmt.Printf("Parsed key:   %x\n", parsedKey.GetKey().Bytes())

	// Example: Try to unmarshal an invalid PEM
	invalidPEM := []byte("-----BEGIN INVALID KEY-----\nABCDEF\n-----END INVALID KEY-----\n")
	_, err = ecc.UnmarshalPEM(invalidPEM)
	if err != nil {
		fmt.Printf("Expected error for invalid PEM: %v\n", err)
	}
}

func Example_marshalPublicPEM() {
	// Generate a random private key and derive its public key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		return
	}
	pubKey, err := privKey.DerivePublicKey()
	if err != nil {
		fmt.Printf("Error deriving public key: %v\n", err)
		return
	}

	// Marshal the public key to PEM format
	pemBytes, err := ecc.MarshalPublicPEM(pubKey)
	if err != nil {
		fmt.Printf("Error marshalling public key to PEM: %v\n", err)
		return
	}

	// Print the PEM-encoded public key
	fmt.Printf("%s", pemBytes)
}

func Example_unmarshalPublicPEM() {
	// Generate a random private key and derive its public key
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		return
	}
	pubKey, err := privKey.DerivePublicKey()
	if err != nil {
		fmt.Printf("Error deriving public key: %v\n", err)
		return
	}

	// Marshal the public key to PEM format
	pemBytes, err := ecc.MarshalPublicPEM(pubKey)
	if err != nil {
		fmt.Printf("Error marshalling public key to PEM: %v\n", err)
		return
	}

	// Unmarshal the PEM back to a CurvePoint
	parsedPubKey, err := ecc.UnmarshalPublicPEM(pemBytes)
	if err != nil {
		fmt.Printf("Error unmarshalling public key PEM: %v\n", err)
		return
	}

	// Show that the original and parsed public keys match
	x1, y1, _ := pubKey.CoordinateIfNotInfinity()
	x2, y2, _ := parsedPubKey.CoordinateIfNotInfinity()
	fmt.Printf("Original public key X: %x\n", x1.Bytes())
	fmt.Printf("Original public key Y: %x\n", y1.Bytes())
	fmt.Printf("Parsed public key X:   %x\n", x2.Bytes())
	fmt.Printf("Parsed public key Y:   %x\n", y2.Bytes())

	// Example: Try to unmarshal an invalid PEM
	invalidPEM := []byte("-----BEGIN INVALID KEY-----\nABCDEF\n-----END INVALID KEY-----\n")
	_, err = ecc.UnmarshalPublicPEM(invalidPEM)
	if err != nil {
		fmt.Printf("Expected error for invalid PEM: %v\n", err)
	}
}
