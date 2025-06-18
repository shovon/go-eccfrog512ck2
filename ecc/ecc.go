package ecc

import (
	"crypto/rand"
	"errors"
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
func (p PrivateKey) DerivePublicKey() (eccfrog512ck2.CurvePoint, error) {
	if p.value == nil {
		return eccfrog512ck2.CurvePoint{}, errors.New("the private key is nil")
	}
	mod := big.NewInt(0)
	mod = mod.Mod(p.value, eccfrog512ck2.GeneratorOrder())
	if mod.Cmp(big.NewInt(0)) == 0 {
		return eccfrog512ck2.CurvePoint{}, errors.New("the private key is either 0, or a multiple of the order of the group")
	}
	return eccfrog512ck2.Generator().Multiply(p.value), nil
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

// ParsePrivateKeySEC1 parses a private key in SEC1 format.
// The SEC1 format for private keys is a simple format where the private key
// is represented as a big-endian integer, optionally prefixed with a version byte.
//
// The function expects the input to be a valid private key value that is:
// 1. Not zero
// 2. Not a multiple of the generator order
// 3. Less than the generator order
func ParsePrivateKeySEC1(data []byte) (PrivateKey, error) {
	if len(data) == 0 {
		return PrivateKey{}, errors.New("empty private key data")
	}

	// Remove version byte if present (0x00)
	if data[0] == 0x00 {
		data = data[1:]
	}

	value := new(big.Int).SetBytes(data)

	// Validate the private key
	if value.Cmp(big.NewInt(0)) == 0 {
		return PrivateKey{}, errors.New("private key cannot be zero")
	}

	mod := new(big.Int).Mod(value, eccfrog512ck2.GeneratorOrder())
	if mod.Cmp(big.NewInt(0)) == 0 {
		return PrivateKey{}, errors.New("private key cannot be a multiple of the generator order")
	}

	if value.Cmp(eccfrog512ck2.GeneratorOrder()) >= 0 {
		return PrivateKey{}, errors.New("private key must be less than the generator order")
	}

	return PrivateKey{value: value}, nil
}

// MarshalSEC1 serializes the private key in SEC1 format.
// The output is a byte slice containing the private key value in big-endian format,
// optionally prefixed with a version byte (0x00).
//
// If includeVersion is true, the output will be prefixed with 0x00.
// If includeVersion is false, the output will be just the raw private key
// value.
func (p PrivateKey) MarshalSEC1(includeVersion bool) []byte {
	if p.value == nil {
		return nil
	}

	keyBytes := p.value.Bytes()
	if !includeVersion {
		return keyBytes
	}

	// Add version byte (0x00) if requested
	return append([]byte{0x00}, keyBytes...)
}

// ParsePublicKeySEC1 parses a public key in SEC1 format.
// The SEC1 format for public keys can be either:
// - Uncompressed: 0x04 || x || y (65 bytes)
// - Compressed: 0x02 || x or 0x03 || x (33 bytes)
// where x and y are the coordinates in big-endian format.
//
// The function returns a CurvePoint representing the public key.
func ParsePublicKeySEC1(data []byte) (eccfrog512ck2.CurvePoint, error) {
	if len(data) == 0 {
		return eccfrog512ck2.CurvePoint{}, errors.New("empty public key data")
	}

	// Check format byte
	switch data[0] {
	case 0x04: // Uncompressed
		if len(data) != 129 { // 1 + 64 + 64 bytes
			return eccfrog512ck2.CurvePoint{}, errors.New("invalid uncompressed public key length")
		}
		x := new(big.Int).SetBytes(data[1:65])
		y := new(big.Int).SetBytes(data[65:129])
		point, err := eccfrog512ck2.NewCurvePoint(x, y)
		if err != nil {
			return eccfrog512ck2.CurvePoint{}, err
		}
		if !eccfrog512ck2.IsCoordinateInCurve([2]*big.Int{x, y}) {
			return eccfrog512ck2.CurvePoint{}, errors.New("point is not on the curve")
		}
		return point, nil

	case 0x02, 0x03: // Compressed
		if len(data) != 65 { // 1 + 64 bytes
			return eccfrog512ck2.CurvePoint{}, errors.New("invalid compressed public key length")
		}
		x := new(big.Int).SetBytes(data[1:65])

		// Calculate y from x using the curve equation: y^2 = x^3 + ax + b (mod p)
		// y^2 = x^3 + ax + b
		y2 := new(big.Int).Mul(x, x)
		y2.Mul(y2, x)
		ax := new(big.Int).Mul(eccfrog512ck2.A(), x)
		y2.Add(y2, ax)
		y2.Add(y2, eccfrog512ck2.B())
		y2.Mod(y2, eccfrog512ck2.P())

		// Calculate y = sqrt(y^2) (mod p)
		y := new(big.Int).ModSqrt(y2, eccfrog512ck2.P())
		if y == nil {
			return eccfrog512ck2.CurvePoint{}, errors.New("invalid compressed public key: no square root exists")
		}

		// If the y coordinate is odd and the format byte is 0x02, or
		// if the y coordinate is even and the format byte is 0x03,
		// we need to negate y
		if (y.Bit(0) == 1) != (data[0] == 0x03) {
			y.Neg(y)
			y.Mod(y, eccfrog512ck2.P())
		}

		point, err := eccfrog512ck2.NewCurvePoint(x, y)
		if err != nil {
			return eccfrog512ck2.CurvePoint{}, err
		}
		if !eccfrog512ck2.IsCoordinateInCurve([2]*big.Int{x, y}) {
			return eccfrog512ck2.CurvePoint{}, errors.New("point is not on the curve")
		}
		return point, nil

	default:
		return eccfrog512ck2.CurvePoint{}, errors.New("invalid public key format")
	}
}
