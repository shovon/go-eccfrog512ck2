package cryptohelpers

import (
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

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
