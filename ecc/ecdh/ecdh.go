package ecdh

import (
	"errors"
	"math/big"
	"sync"

	"github.com/shovon/go-eccfrog512ck2"
)

type ECDHPrivateKey big.Int

func (e ECDHPrivateKey) DeriveSharedSecret(publicKey eccfrog512ck2.CurvePoint) ([]byte, error) {
	sharedCurvePoint := publicKey.Multiply((*big.Int)(&e))
	var secret []byte
	var wg sync.WaitGroup
	wg.Add(1)
	if !sharedCurvePoint.IfNotInfinity(func(coordinate [2]*big.Int) {
		secret = coordinate[0].Bytes()
		wg.Done()
	}) {
		return nil, errors.New("the other party's public key cannot be the point at infinity")
	}
	wg.Wait()
	return secret, nil
}
