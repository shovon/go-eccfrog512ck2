package ecc

import (
	"crypto/rand"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2"
)

// GeneratePrivateKey generates a random private key.
//
// Effectively a shorthand for `rand.Int(rand.Reader, GeneratorOrder())`
func GeneratePrivateKey() (*big.Int, error) {
	return rand.Int(rand.Reader, eccfrog512ck2.GeneratorOrder())
}

// GetPublicKey gets the public key associated with the random private key.
func GetPublicKey(privateKey *big.Int) eccfrog512ck2.CurvePoint {
	return eccfrog512ck2.Generator().Multiply(privateKey)
}
