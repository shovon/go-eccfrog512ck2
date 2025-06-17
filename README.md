# Eccfrog512ck2 in Go

A Go implementation of the [EccFrog512ck2 Weierstrass curve family](https://billatnapier.medium.com/eccfrog512ck2-an-enhanced-512-bit-weierstrass-elliptic-curve-97563d79b6c9) for elliptic curve cryptography. This library provides a robust set of cryptographic primitives for secure communication and digital signatures.

## Features

- **Elliptic Curve Diffie-Hellman (ECDH)**: Secure key exchange between parties
- **Elliptic Curve Digital Signature Algorithm (ECDSA)**: Digital signatures for message authentication
- **Elliptic Curve Integrated Encryption Scheme (ECIES)**: Asymmetric encryption with AES-GCM-256

## Installation

```bash
go get github.com/shovon/go-eccfrog512ck2
```

## Usage

### ECDH Key Exchange

```go
import "github.com/shovon/go-eccfrog512ck2/ecc/ecdh"

// Generate private keys for both parties
alicePrivateKey, _ := ecc.GeneratePrivateKey()
bobPrivateKey, _ := ecc.GeneratePrivateKey()

// Derive public keys
alicePublicKey, _ := alicePrivateKey.DerivePublicKey()
bobPublicKey, _ := bobPrivateKey.DerivePublicKey()

// Derive shared secret
aliceSharedSecret, _ := ecdh.ECDHPrivateKey(alicePrivateKey).DeriveSharedSecret(bobPublicKey)
bobSharedSecret, _ := ecdh.ECDHPrivateKey(bobPrivateKey).DeriveSharedSecret(alicePublicKey)
// aliceSharedSecret == bobSharedSecret
```

### ECDSA Signatures

```go
import (
    "crypto/sha256"
    "github.com/shovon/go-eccfrog512ck2/ecc/ecdsa"
)

// Generate key pair
privateKey, _ := ecc.GeneratePrivateKey()
publicKey, _ := privateKey.DerivePublicKey()

// Sign a message
message := []byte("Hello, World!")
signer := ecdsa.NewSign(sha256.New, privateKey)
r, s, _ := signer.Sign(message)

// Verify signature
verifier := ecdsa.NewVerification(sha256.New, publicKey)
valid, _ := verifier.Verify([2]*big.Int{r, s}, message)
```

### ECIES Encryption

```go
import (
    "crypto/sha256"
    "github.com/shovon/go-eccfrog512ck2/ecc/ecies"
    "github.com/shovon/go-eccfrog512ck2/ecc/cryptohelpers"
)

// Generate key pairs
alicePrivateKey, _ := ecc.GeneratePrivateKey()
bobPrivateKey, _ := ecc.GeneratePrivateKey()
bobPublicKey, _ := bobPrivateKey.DerivePublicKey()

// Encrypt message
message := []byte("Secret message")
kdf := cryptohelpers.HKDF256(sha256.New)
rG, ciphertext, _ := ecies.
  NewEncryptor(cryptohelpers.AESGCM256Encrypt(kdf)).
  Encrypt(alicePrivateKey, bobPublicKey, message)

// Decrypt message
plaintext, _ := ecies.
  NewDecryptor(cryptohelpers.AESGCM256Decrypt(kdf)).
  Decrypt(bobPrivateKey, rG, result)
```

## Security

This implementation uses the EccFrog512ck2 Weierstrass curve family, which provides strong security guarantees for:

- Key exchange via ECDH
- Digital signatures via ECDSA
- Asymmetric encryption via ECIES with AES-GCM-256

## TODO

- [ ] CLI that somewhat resembles OpenSSL
  - [x] generate keys
  - [x] parse keys
  - [x] sign
  - [x] verify
  - [x] encrypt/decrypt
  - [x] generate shared secret
- [ ] Publish to gopkg

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for the full license text.
