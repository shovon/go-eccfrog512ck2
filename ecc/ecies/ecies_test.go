package ecies_test

import (
	"crypto/sha256"
	"testing"

	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/cryptohelpers"
	"github.com/shovon/go-eccfrog512ck2/ecc/ecies"
)

func TestEncryptDecrypt(t *testing.T) {
	message := []byte("Hello, World!")

	alicePrivateKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	bobPrivateKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	kdf := cryptohelpers.HKDF256(sha256.New)
	rG, result, err := ecies.Encryptor[cryptohelpers.AESGCMResults](
		cryptohelpers.AESGCM256KDFEncrypt(kdf),
	).Encrypt(alicePrivateKey, bobPrivateKey.DerivePublicKey(), message)

	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	plaintext, err := ecies.Decryptor[cryptohelpers.AESGCMResults](
		cryptohelpers.AESGCM256KDFDecrypt(kdf),
	).Decrypt(bobPrivateKey, rG, result)

	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if string(plaintext) != string(message) {
		t.Logf("expected %q but got %q", message, plaintext)
		t.FailNow()
	}
}
