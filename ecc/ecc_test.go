package ecc_test

import (
	"math/big"
	"testing"

	"github.com/shovon/go-eccfrog512ck2"
	"github.com/shovon/go-eccfrog512ck2/ecc"
)

func TestParsePrivateKeySEC1(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "zero value",
			data:    []byte{0x00},
			wantErr: true,
		},
		{
			name:    "multiple of generator order",
			data:    eccfrog512ck2.GeneratorOrder().Bytes(),
			wantErr: true,
		},
		{
			name:    "greater than generator order",
			data:    new(big.Int).Add(eccfrog512ck2.GeneratorOrder(), big.NewInt(1)).Bytes(),
			wantErr: true,
		},
		{
			name:    "valid key with version byte",
			data:    append([]byte{0x00}, big.NewInt(12345).Bytes()...),
			wantErr: false,
		},
		{
			name:    "valid key without version byte",
			data:    big.NewInt(12345).Bytes(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecc.ParsePrivateKeySEC1(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKeySEC1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify the key is valid by deriving a public key
				if _, err := key.DerivePublicKey(); err != nil {
					t.Errorf("Derived public key is invalid: %v", err)
				}
			}
		})
	}
}

func TestPrivateKeyMarshalSEC1(t *testing.T) {
	tests := []struct {
		name           string
		key            ecc.PrivateKey
		includeVersion bool
		want           []byte
	}{
		{
			name:           "nil key",
			key:            ecc.PrivateKey{},
			includeVersion: false,
			want:           nil,
		},
		{
			name:           "small value without version",
			key:            mustParseKey(t, big.NewInt(12345).Bytes()),
			includeVersion: false,
			want:           big.NewInt(12345).Bytes(),
		},
		{
			name:           "small value with version",
			key:            mustParseKey(t, big.NewInt(12345).Bytes()),
			includeVersion: true,
			want:           append([]byte{0x00}, big.NewInt(12345).Bytes()...),
		},
		{
			name:           "large value without version",
			key:            mustParseKey(t, new(big.Int).Sub(eccfrog512ck2.GeneratorOrder(), big.NewInt(1)).Bytes()),
			includeVersion: false,
			want:           new(big.Int).Sub(eccfrog512ck2.GeneratorOrder(), big.NewInt(1)).Bytes(),
		},
		{
			name:           "large value with version",
			key:            mustParseKey(t, new(big.Int).Sub(eccfrog512ck2.GeneratorOrder(), big.NewInt(1)).Bytes()),
			includeVersion: true,
			want:           append([]byte{0x00}, new(big.Int).Sub(eccfrog512ck2.GeneratorOrder(), big.NewInt(1)).Bytes()...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.key.MarshalSEC1(tt.includeVersion)
			if len(got) != len(tt.want) {
				t.Errorf("MarshalSEC1() length = %v, want %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("MarshalSEC1()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParsePublicKeySEC1(t *testing.T) {
	// Generate a test key pair
	privKey, err := ecc.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	pubKey, err := privKey.DerivePublicKey()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	// Get coordinates for testing
	x, y, ok := pubKey.CoordinateIfNotInfinity()
	if !ok {
		t.Fatal("Public key is point at infinity")
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid format byte",
			data:    []byte{0x01},
			wantErr: true,
		},
		{
			name:    "invalid uncompressed length",
			data:    append([]byte{0x04}, make([]byte, 128)...),
			wantErr: true,
		},
		{
			name:    "invalid compressed length",
			data:    append([]byte{0x02}, make([]byte, 64)...),
			wantErr: true,
		},
		{
			name:    "valid uncompressed",
			data:    append([]byte{0x04}, append(x.Bytes(), y.Bytes()...)...),
			wantErr: false,
		},
		{
			name:    "valid compressed (even y)",
			data:    append([]byte{0x02}, x.Bytes()...),
			wantErr: false,
		},
		{
			name:    "valid compressed (odd y)",
			data:    append([]byte{0x03}, x.Bytes()...),
			wantErr: false,
		},
		{
			name:    "point not on curve",
			data:    append([]byte{0x04}, append(big.NewInt(0).Bytes(), big.NewInt(0).Bytes()...)...),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ecc.ParsePublicKeySEC1(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePublicKeySEC1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// For valid cases, verify the point is on the curve
				if x, y, ok := got.CoordinateIfNotInfinity(); !ok || !eccfrog512ck2.IsCoordinateInCurve([2]*big.Int{x, y}) {
					t.Error("Parsed point is not on the curve")
				}
			}
		})
	}
}

// mustParseKey is a helper function that creates a PrivateKey from bytes,
// failing the test if parsing fails.
func mustParseKey(t *testing.T, data []byte) ecc.PrivateKey {
	key, err := ecc.ParsePrivateKeySEC1(data)
	if err != nil {
		t.Fatalf("Failed to parse test key: %v", err)
	}
	return key
}
