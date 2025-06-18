package cryptohelpers

import (
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF256 returns a key derivation function that uses HKDF-SHA256 to derive a
// 32-byte key. It takes a hash function constructor as input and returns a
// function that accepts a secret key and produces a derived 32-byte key.
//
// The returned function uses HKDF (HMAC-based Key Derivation Function) with the
// provided hash function to derive a cryptographically secure key from the
// input secret. No salt or info parameters are used in the derivation.
//
// Parameters:
//   - hash: A function that returns a new hash.Hash instance (e.g. sha256.New)
//
// Returns:
//   - A function that takes a SecretKey and returns a 32-byte array and error
func HKDF256(hash func() hash.Hash) func(secret SecretKey) ([32]byte, error) {
	return func(secret SecretKey) ([32]byte, error) {
		// Use HKDF-SHA256 to derive a 32-byte key from the secret
		h := hkdf.New(hash, secret, nil, nil)
		var key [32]byte
		if _, err := io.ReadFull(h, key[:]); err != nil {
			return key, err
		}
		return key, nil
	}
}
