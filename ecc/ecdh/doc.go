// Package ecdh provides helpers for performing Elliptic Curve Diffie-Hellman
// (ECDH) key exchange using the EccFrog512ck2 elliptic curve. This package
// defines types and functions to derive shared secrets between parties using
// their private and public keys.
//
// The main type is ECDHPrivateKey, which wraps a private key and provides the
// DeriveSharedSecret method to compute a shared secret given another party's public key.
//
// This package is intended for use with the eccfrog512ck2 curve and integrates with
// the ecc package's key types.
//
// Example usage:
//
//	alicePriv, _ := ecc.GeneratePrivateKey()
//	bobPriv, _ := ecc.GeneratePrivateKey()
//	aliceECDH := ecdh.ECDHPrivateKey(alicePriv)
//	bobECDH := ecdh.ECDHPrivateKey(bobPriv)
//	alicePub, _ := alicePriv.DerivePublicKey()
//	bobPub, _ := bobPriv.DerivePublicKey()
//	aliceShared, _ := aliceECDH.DeriveSharedSecret(bobPub)
//	bobShared, _ := bobECDH.DeriveSharedSecret(alicePub)
//	// aliceShared and bobShared should be equal
package ecdh
