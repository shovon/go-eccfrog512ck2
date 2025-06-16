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

type AESGCM256KDFResults struct {
	CipherText []byte
	Nonce      []byte
}

func AESGCM256KDFEncrypt(
	kdf func(SecretKey) ([32]byte, error),
) func(SecretKey, []byte) (AESGCM256KDFResults, error) {
	return func(secret SecretKey, plaintext []byte) (AESGCM256KDFResults, error) {
		// Use HKDF-SHA256 to derive a 32-byte key from the secret
		h := hkdf.New(sha256.New, secret, nil, nil)
		key := make([]byte, 32)
		if _, err := io.ReadFull(h, key); err != nil {
			return AESGCM256KDFResults{}, err
		}

		if len(key) != 32 {
			return AESGCM256KDFResults{}, fmt.Errorf("key must be 32 bytes")
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return AESGCM256KDFResults{}, err
		}

		// GCM mode
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return AESGCM256KDFResults{}, err
		}

		// Generate random nonce
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return AESGCM256KDFResults{}, err
		}

		// Encrypt
		ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
		return AESGCM256KDFResults{CipherText: ciphertext, Nonce: nonce}, nil
	}
}

func AESGCM256KDFDecrypt(
	kdf func(SecretKey) ([32]byte, error),
) func(SecretKey, AESGCM256KDFResults) ([]byte, error) {
	return func(secret SecretKey, nonceCiphertext AESGCM256KDFResults) ([]byte, error) {
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
		plaintext, err := aesGCM.Open(nil, nonceCiphertext.Nonce, nonceCiphertext.CipherText, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}
}
