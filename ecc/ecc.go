package ecc

import (
	"crypto/rand"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2"
)

type PrivateKey struct {
	value *big.Int
}

func (p PrivateKey) GetKey() *big.Int {
	return (&big.Int{}).Set(p.value)
}

// GeneratePrivateKey generates a random private key.
//
// Effectively a shorthand for `rand.Int(rand.Reader, GeneratorOrder())`
func GeneratePrivateKey() (PrivateKey, error) {
	value, err := rand.Int(rand.Reader, eccfrog512ck2.GeneratorOrder())
	return PrivateKey{value: value}, err
}

// GetPublicKey gets the public key associated with the random private key.
func GetPublicKey(privateKey PrivateKey) eccfrog512ck2.CurvePoint {
	return eccfrog512ck2.Generator().Multiply(privateKey.value)
}
