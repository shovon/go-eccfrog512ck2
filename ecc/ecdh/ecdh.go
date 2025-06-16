package ecdh

import (
	"errors"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2"
	"github.com/shovon/go-eccfrog512ck2/ecc"
)

type ECDHPrivateKey ecc.PrivateKey

func (e ECDHPrivateKey) DeriveSharedSecret(publicKey eccfrog512ck2.CurvePoint) ([]byte, error) {
	if x, _, ok := publicKey.Multiply((*big.Int)(ecc.PrivateKey(e).GetKey())).CoordinateIfNotInfinity(); ok {
		return x.Bytes(), nil
	}
	return nil, errors.New("either the other party's public key was the point at infinity, or the private key was either 0 or the multiple of the order of the curve")
}
