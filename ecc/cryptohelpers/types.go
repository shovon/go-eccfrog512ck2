package cryptohelpers

// SecretKey represents a byte slice used as a cryptographic secret key. It is
// used by the AES-GCM encryption/decryption functions and HKDF key derivation.
type SecretKey []byte
