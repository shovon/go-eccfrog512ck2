package ecies

import (
	"crypto/rand"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2"
	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/cryptohelpers"
)

// Encryptor is a generic function type that takes a secret key and plaintext
// bytes, and returns an encrypted ciphertext of type C along with any error.
// The generic type C allows for different ciphertext formats to be used with
// the same encryption logic.
type Encryptor[C any] func(cryptohelpers.SecretKey, []byte) (C, error)

// Encrypt performs ECIES encryption using the provided private key, public key
// and message. It returns an ephemeral public key and encrypted ciphertext.
//
// Returns:
// - The ephemeral public key rG
// - The encrypted ciphertext of type C
// - Any error that occurred during encryption
func (e Encryptor[C]) Encrypt(
	privateKey ecc.PrivateKey,
	publicKey eccfrog512ck2.CurvePoint,
	message []byte,
) (eccfrog512ck2.CurvePoint, C, error) {
	var defaultC C
	r, err := rand.Int(rand.Reader, eccfrog512ck2.GeneratorOrder())
	if err != nil {
		return eccfrog512ck2.PointAtInfinity(), defaultC, err
	}
	rG := eccfrog512ck2.Generator().Multiply(r)

	s := publicKey.Multiply(r)
	secret, _, _ := s.CoordinateIfNotInfinity()
	secretCopy := (&big.Int{}).Set(secret).Bytes()

	ciphertext, err := e(secretCopy, message)
	if err != nil {
		return eccfrog512ck2.PointAtInfinity(), defaultC, err
	}

	return rG, ciphertext, nil
}

// Decryptor is a generic function type that takes a secret key and ciphertext
// of type C, and returns the decrypted plaintext bytes along with any error.
// The generic type C allows for different ciphertext formats to be used with
// the same decryption logic.
type Decryptor[C any] func(cryptohelpers.SecretKey, C) ([]byte, error)

func (e Decryptor[C]) Decrypt(
	privateKey ecc.PrivateKey,
	publicKey eccfrog512ck2.CurvePoint,
	rG eccfrog512ck2.CurvePoint,
	ciphertext C,
) ([]byte, error) {
	s := publicKey.Multiply(privateKey.GetKey())
	secret, _, _ := s.CoordinateIfNotInfinity()
	secretCopy := (&big.Int{}).Set(secret).Bytes()

	plaintext, err := e(secretCopy, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
