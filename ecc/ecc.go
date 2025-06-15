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

// GetPublicKey gets the public key associated with the random private key.
func (p PrivateKey) DerivePublicKey() eccfrog512ck2.CurvePoint {
	return eccfrog512ck2.Generator().Multiply(p.value)
}

func sub1(value *big.Int) *big.Int {
	return value.Sub(value, big.NewInt(1))
}

func add1(value *big.Int) *big.Int {
	return value.Add(value, big.NewInt(1))
}

// GeneratePrivateKey generates a random private key.
//
// Effectively a shorthand for `rand.Int(rand.Reader, GeneratorOrder())`
func GeneratePrivateKey() (PrivateKey, error) {
	value, err := rand.Int(rand.Reader, sub1(eccfrog512ck2.GeneratorOrder()))
	return PrivateKey{value: add1(value)}, err
}
