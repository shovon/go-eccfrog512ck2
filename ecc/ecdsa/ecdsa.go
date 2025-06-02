package ecdsa

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2"
	"github.com/shovon/go-eccfrog512ck2/ecc"
)

type Params struct {
	Hasher func(input []byte) ([]byte, error)
}

type SignParams struct {
	Params
	PrivateKey ecc.PrivateKey
}

type VerificationParams struct {
	Params
	PublicKey eccfrog512ck2.CurvePoint
}

func extractLeftMostBits(num *big.Int, n int) *big.Int {
	// Get the total number of bits in the big.Int number
	totalBits := num.BitLen()

	// If n is greater than or equal to the total number of bits, return the number as is
	if n >= totalBits {
		return new(big.Int).Set(num)
	}

	// Calculate the number of bits to shift right
	bitsToShift := totalBits - n

	// Shift the number to the right to discard the least significant bits
	leftMostBits := new(big.Int).Rsh(num, uint(bitsToShift))

	return leftMostBits
}

func (signParams SignParams) Sign(message []byte) (*big.Int, *big.Int, error) {
	hashbytes, err := signParams.Params.Hasher(message)
	if err != nil {
		return nil, nil, err
	}

	generatorOrder := eccfrog512ck2.GeneratorOrder()

	z := extractLeftMostBits(big.NewInt(0).SetBytes(hashbytes), generatorOrder.BitLen())

	var k *big.Int
	k = big.NewInt(0)
	s := big.NewInt(0)
	r := big.NewInt(0)

	for s.Cmp(big.NewInt(0)) == 0 || r.Cmp(big.NewInt(0)) == 0 {
		for k.Cmp(big.NewInt(0)) == 0 {
			k, err = rand.Int(rand.Reader, generatorOrder)
			if err != nil {
				panic(err)
			}
		}

		p := eccfrog512ck2.Generator().Multiply(k)

		if x, _, ok := p.CoordinateIfNotInfinity(); !ok {
			r = r.Mod(x, generatorOrder)
			kInverse := k.ModInverse(k, generatorOrder)
			s = s.Mul(r, (signParams.PrivateKey.GetKey())).Add(s, z).Mul(s, kInverse)
			s.Mod(s, generatorOrder)
		} else {
			return nil, nil, errors.New("can't operate with the point at infinity")
		}
	}

	return r, s, nil
}

func (params VerificationParams) Verify(hasher func(input []byte) ([]byte, error), signature [2]*big.Int, message []byte) (bool, error) {
	generatorOrder := eccfrog512ck2.GeneratorOrder()

	hashBytes, err := hasher(message)
	if err != nil {
		return false, err
	}

	z := extractLeftMostBits(big.NewInt(0).SetBytes(hashBytes), (*big.Int)(generatorOrder).BitLen())
	sInverse := big.NewInt(0).ModInverse(signature[1], generatorOrder)

	u1 := big.NewInt(0).Mod(big.NewInt(0).Mul(z, sInverse), generatorOrder)
	u2 := big.NewInt(0).Mod(big.NewInt(0).Mul(signature[0], sInverse), generatorOrder)

	if x, _, ok := eccfrog512ck2.Generator().Multiply(u1).Add(params.PublicKey.Multiply(u2)).CoordinateIfNotInfinity(); !ok {
		return signature[0].Cmp(x) == 0, nil
	}

	panic("Fatal error: verification yielded a point at infinity, which should be impossible")
}
