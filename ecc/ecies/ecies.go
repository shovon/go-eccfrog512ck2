package ecies

import (
	"crypto/rand"
	"math/big"

	"github.com/shovon/go-eccfrog512ck2"
	"github.com/shovon/go-eccfrog512ck2/ecc"
)

type (
	MacKey        []byte
	EncryptionKey []byte
	Ciphertext    []byte
	MAC           []byte
)
type ECIESParams struct {
	KDF        func([]byte) ([]byte, []byte, error)
	MAC        func(MacKey, []byte) ([]byte, error)
	Encryptor  func(EncryptionKey, []byte) ([]byte, error)
	PrivateKey ecc.PrivateKey
	PublicKey  eccfrog512ck2.CurvePoint
}

func (e ECIESParams) Encrypt(message []byte) (eccfrog512ck2.CurvePoint, Ciphertext, MAC, error) {
	r, err := rand.Int(rand.Reader, eccfrog512ck2.GeneratorOrder())
	if err != nil {
		return eccfrog512ck2.PointAtInfinity(), nil, nil, err
	}
	rG := eccfrog512ck2.Generator().Multiply(r)

	s := e.PublicKey.Multiply(r)
	secret, _, _ := s.CoordinateIfNotInfinity()
	secretCopy := (&big.Int{}).Set(secret).Bytes()

	encKey, macKey, err := e.KDF(secretCopy)
	if err != nil {
		return eccfrog512ck2.PointAtInfinity(), nil, nil, err
	}
	ciphertext, err := e.Encryptor(EncryptionKey(encKey), message)
	if err != nil {
		return eccfrog512ck2.PointAtInfinity(), nil, nil, err
	}

	mac, err := e.MAC(MacKey(macKey), ciphertext)
	if err != nil {
		return eccfrog512ck2.PointAtInfinity(), nil, nil, err
	}

	return rG, ciphertext, mac, nil
}

func ECIESECCFrog512Ck2HKDF2SHA256AES256GCM() ECIESParams {
	return ECIESParams{
		// TODO: fill this up
		// // TODO
		// KDF: nil,
		// // TODO
		// MAC: nil,
		// // TODO
		// Encryptor: nil,
		// // TODO
		// PrivateKey: nil,
		// // TODO
		// PublicKey: eccfrog512ck2.PointAtInfinity(),
	}
}
