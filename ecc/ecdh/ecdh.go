package ecdh

import (
	"errors"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2"
)

type ECDHPrivateKey big.Int

func (e ECDHPrivateKey) DeriveSharedSecret(publicKey eccfrog512ck2.CurvePoint) ([]byte, error) {
	if x, _, ok := publicKey.Multiply((*big.Int)(&e)).CoordinateIfNotInfinity(); ok {
		return x.Bytes(), nil
	}
	return nil, errors.New("the other party's public key cannot be the point at infinity")
}
