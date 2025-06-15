package ecies

import (
	"crypto/rand"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2"
	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/cryptohelpers"
)

type Encryptor[C any] func(cryptohelpers.SecretKey, []byte) (C, error)

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

type Decryptor[C any] func(cryptohelpers.SecretKey, C) ([]byte, error)

func (e Decryptor[C]) Decrypt(
	privateKey ecc.PrivateKey,
	ephemeralPublicKey eccfrog512ck2.CurvePoint,
	ciphertext C,
) ([]byte, error) {
	s := ephemeralPublicKey.Multiply(privateKey.GetKey())
	secret, _, _ := s.CoordinateIfNotInfinity()
	secretCopy := (&big.Int{}).Set(secret).Bytes()

	plaintext, err := e(secretCopy, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
