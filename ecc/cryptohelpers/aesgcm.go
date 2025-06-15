package cryptohelpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type AESGCMResults struct {
	CipherText []byte
	Nonce      []byte
}

func AESGCM256Encrypt(secret SecretKey, plaintext []byte) (AESGCMResults, error) {
	// Use HKDF-SHA256 to derive a 32-byte key from the secret
	h := hkdf.New(sha256.New, secret, nil, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return AESGCMResults{}, err
	}

	if len(key) != 32 {
		return AESGCMResults{}, fmt.Errorf("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return AESGCMResults{}, err
	}

	// GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return AESGCMResults{}, err
	}

	// Generate random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return AESGCMResults{}, err
	}

	// Encrypt
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return AESGCMResults{CipherText: ciphertext, Nonce: nonce}, nil
}

func AESGCM256Decrypt(secret SecretKey, results AESGCMResults) ([]byte, error) {
	// Use HKDF-SHA256 to derive a 32-byte key from the secret
	h := hkdf.New(sha256.New, secret, nil, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := aesGCM.Open(nil, results.Nonce, results.CipherText, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
