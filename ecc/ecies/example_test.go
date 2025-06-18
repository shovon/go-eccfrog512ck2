package ecies

import (
	"crypto/sha256"
	"fmt"

	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/cryptohelpers"
)

// Example_encryptDecrypt demonstrates ECIES encryption and decryption.
func Example_encryptDecrypt() {
	message := []byte("Hello, World!")

	alicePrivateKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Println("Error generating Alice's private key:", err)
		return
	}

	bobPrivateKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		fmt.Println("Error generating Bob's private key:", err)
		return
	}
	bobPublicKey, err := bobPrivateKey.DerivePublicKey()
	if err != nil {
		fmt.Println("Error deriving Bob's public key:", err)
		return
	}

	kdf := cryptohelpers.HKDF256(sha256.New)
	rG, ciphertext, err := NewEncryptor(cryptohelpers.AES256GCMEncrypt(kdf)).
		Encrypt(alicePrivateKey, bobPublicKey, message)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	plaintext, err := NewDecryptor(cryptohelpers.AES256GCMDecrypt(kdf)).
		Decrypt(bobPrivateKey, rG, ciphertext)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Printf("Decrypted message: %s\n", plaintext)
	// Output:
	// Decrypted message: Hello, World!
}
