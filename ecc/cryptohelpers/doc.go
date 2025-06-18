// Package cryptohelpers provides cryptographic utility functions for secure key
// derivation and authenticated encryption.
//
// The package implements AES-256-GCM authenticated encryption and HKDF key
// derivation functions. The main components are:
//
// SecretKey - A type representing cryptographic secret key material
//
// AES256GCMResults - A struct containing ciphertext and nonce for AES-GCM encryption
//
// AES256GCMEncrypt - Creates an encryption function using AES-256-GCM with a KDF
//
// AES256GCMDecrypt - Creates a decryption function using AES-256-GCM with a KDF
//
// HKDF256 - Creates a key derivation function using HKDF with SHA-256
//
// The encryption functions use AES-256 in Galois/Counter Mode (GCM) which provides
// both confidentiality and authenticity. The key derivation uses HKDF (HMAC-based
// Key Derivation Function) to derive encryption keys from secret key material.

package cryptohelpers
