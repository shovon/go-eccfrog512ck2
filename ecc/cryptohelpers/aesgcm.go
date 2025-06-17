package cryptohelpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AESGCM256Results struct {
	CipherText []byte
	Nonce      []byte
}

func AESGCM256Encrypt(
	kdf func(SecretKey) ([32]byte, error),
) func(SecretKey, []byte) (AESGCM256Results, error) {
	return func(secret SecretKey, plaintext []byte) (AESGCM256Results, error) {
		// Use HKDF-SHA256 to derive a 32-byte key from the secret
		key, err := kdf(secret)
		if err != nil {
			return AESGCM256Results{}, err
		}

		block, err := aes.NewCipher(key[:])
		if err != nil {
			return AESGCM256Results{}, err
		}

		// GCM mode
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return AESGCM256Results{}, err
		}

		// Generate random nonce
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return AESGCM256Results{}, err
		}

		// Encrypt
		ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
		return AESGCM256Results{CipherText: ciphertext, Nonce: nonce}, nil
	}
}

func AESGCM256Decrypt(
	kdf func(SecretKey) ([32]byte, error),
) func(SecretKey, AESGCM256Results) ([]byte, error) {
	return func(secret SecretKey, nonceCiphertext AESGCM256Results) ([]byte, error) {
		// Use HKDF-SHA256 to derive a 32-byte key from the secret
		key, err := kdf(secret)
		if err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(key[:])
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
