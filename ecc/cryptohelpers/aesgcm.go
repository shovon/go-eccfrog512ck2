package cryptohelpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AES256GCMResults struct {
	CipherText []byte
	Nonce      []byte
}

func AES256GCMEncrypt(
	kdf func(SecretKey) ([32]byte, error),
) func(SecretKey, []byte) (AES256GCMResults, error) {
	return func(secret SecretKey, plaintext []byte) (AES256GCMResults, error) {
		// Use HKDF-SHA256 to derive a 32-byte key from the secret
		key, err := kdf(secret)
		if err != nil {
			return AES256GCMResults{}, err
		}

		block, err := aes.NewCipher(key[:])
		if err != nil {
			return AES256GCMResults{}, err
		}

		// GCM mode
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return AES256GCMResults{}, err
		}

		// Generate random nonce
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return AES256GCMResults{}, err
		}

		// Encrypt
		ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
		return AES256GCMResults{CipherText: ciphertext, Nonce: nonce}, nil
	}
}

func AES256GCMDecrypt(
	kdf func(SecretKey) ([32]byte, error),
) func(SecretKey, AES256GCMResults) ([]byte, error) {
	return func(secret SecretKey, nonceCiphertext AES256GCMResults) ([]byte, error) {
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
