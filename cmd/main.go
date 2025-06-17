package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"

	"github.com/shovon/go-eccfrog512ck2/ecc"
	"github.com/shovon/go-eccfrog512ck2/ecc/cryptohelpers"
	"github.com/shovon/go-eccfrog512ck2/ecc/ecdh"
	"github.com/shovon/go-eccfrog512ck2/ecc/ecdsa"
	"github.com/shovon/go-eccfrog512ck2/ecc/ecies"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "eccfrog512ck2",
	Short: "CLI tool for Eccfrog512ck2 curve operations",
	Long: `A command line tool for cryptographic operations using the Eccfrog512ck2 curve.
It provides functionality for key generation, signing, verification, encryption, and key exchange.`,
}

var genpkeyCmd = &cobra.Command{
	Use:   "genpkey",
	Short: "Generate a private key",
	Long:  `Generate a new private key and save it to a file in PEM format.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		outFile, _ := cmd.Flags().GetString("out")
		if outFile == "" {
			return fmt.Errorf("output file is required")
		}

		// Generate private key
		privateKey, err := ecc.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %v", err)
		}

		// Convert to PEM format and save
		pemBytes, err := privateKey.MarshalPEM()
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %v", err)
		}

		if err := os.WriteFile(outFile, pemBytes, 0600); err != nil {
			return fmt.Errorf("failed to write private key: %v", err)
		}

		fmt.Printf("Private key written to %s\n", outFile)
		return nil
	},
}

var pkeyCmd = &cobra.Command{
	Use:   "pkey",
	Short: "Public key operations",
	Long:  `Operations on private/public keys including deriving public keys from private keys.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		inFile, _ := cmd.Flags().GetString("in")
		outFile, _ := cmd.Flags().GetString("out")
		pubout, _ := cmd.Flags().GetBool("pubout")

		if inFile == "" {
			return fmt.Errorf("input file is required")
		}
		if outFile == "" {
			return fmt.Errorf("output file is required")
		}
		if !pubout {
			return fmt.Errorf("currently only --pubout is supported")
		}

		// Read private key
		pemBytes, err := os.ReadFile(inFile)
		if err != nil {
			return fmt.Errorf("failed to read private key: %v", err)
		}

		// Parse private key
		privateKey, err := ecc.UnmarshalPEM(pemBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}

		// Derive public key
		publicKey, err := privateKey.DerivePublicKey()
		if err != nil {
			return fmt.Errorf("failed to derive public key: %v", err)
		}

		// Convert to PEM format and save
		pemBytes, err = ecc.MarshalPublicPEM(publicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %v", err)
		}

		if err := os.WriteFile(outFile, pemBytes, 0644); err != nil {
			return fmt.Errorf("failed to write public key: %v", err)
		}

		fmt.Printf("Public key written to %s\n", outFile)
		return nil
	},
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a file",
	Long:  `Sign a file using ECDSA with SHA-256.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		inFile, _ := cmd.Flags().GetString("in")
		outFile, _ := cmd.Flags().GetString("out")
		keyFile, _ := cmd.Flags().GetString("inkey")

		if inFile == "" {
			return fmt.Errorf("input file is required")
		}
		if outFile == "" {
			return fmt.Errorf("output file is required")
		}
		if keyFile == "" {
			return fmt.Errorf("private key file is required")
		}

		// Read private key
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key: %v", err)
		}

		// Parse private key
		privateKey, err := ecc.UnmarshalPEM(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}

		// Read input file
		message, err := os.ReadFile(inFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		// Sign message
		signer := ecdsa.NewSign(sha256.New, privateKey)
		r, s, err := signer.Sign(message)
		if err != nil {
			return fmt.Errorf("failed to sign message: %v", err)
		}

		// Write signature to output file
		signature := append(r.Bytes(), s.Bytes()...)
		if err := os.WriteFile(outFile, signature, 0644); err != nil {
			return fmt.Errorf("failed to write signature: %v", err)
		}

		fmt.Printf("Signature written to %s\n", outFile)
		return nil
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature",
	Long:  `Verify an ECDSA signature using SHA-256.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		inFile, _ := cmd.Flags().GetString("in")
		sigFile, _ := cmd.Flags().GetString("sigfile")
		keyFile, _ := cmd.Flags().GetString("inkey")

		if inFile == "" {
			return fmt.Errorf("input file is required")
		}
		if sigFile == "" {
			return fmt.Errorf("signature file is required")
		}
		if keyFile == "" {
			return fmt.Errorf("public key file is required")
		}

		// Read public key
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key: %v", err)
		}

		// Parse public key
		publicKey, err := ecc.UnmarshalPublicPEM(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %v", err)
		}

		// Read input file
		message, err := os.ReadFile(inFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		// Read signature file
		sigBytes, err := os.ReadFile(sigFile)
		if err != nil {
			return fmt.Errorf("failed to read signature file: %v", err)
		}

		// Split signature into r and s components
		if len(sigBytes) != 128 { // 64 bytes for r + 64 bytes for s
			return fmt.Errorf("invalid signature length")
		}
		r := new(big.Int).SetBytes(sigBytes[:64])
		s := new(big.Int).SetBytes(sigBytes[64:])

		// Verify signature
		verifier := ecdsa.NewVerification(sha256.New, publicKey)
		valid, err := verifier.Verify([2]*big.Int{r, s}, message)
		if err != nil {
			return fmt.Errorf("failed to verify signature: %v", err)
		}

		if valid {
			fmt.Println("Signature is valid")
		} else {
			fmt.Println("Signature is invalid")
			os.Exit(1)
		}
		return nil
	},
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file",
	Long:  `Encrypt a file using ECIES with AES-GCM-256.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		inFile, _ := cmd.Flags().GetString("in")
		outFile, _ := cmd.Flags().GetString("out")
		keyFile, _ := cmd.Flags().GetString("inkey")

		if inFile == "" {
			return fmt.Errorf("input file is required")
		}
		if outFile == "" {
			return fmt.Errorf("output file is required")
		}
		if keyFile == "" {
			return fmt.Errorf("public key file is required")
		}

		// Read public key
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key: %v", err)
		}

		// Parse public key
		publicKey, err := ecc.UnmarshalPublicPEM(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %v", err)
		}

		// Read input file
		message, err := os.ReadFile(inFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		// Generate ephemeral key pair
		ephemeralKey, err := ecc.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate ephemeral key: %v", err)
		}

		// Encrypt message
		kdf := cryptohelpers.HKDF256(sha256.New)
		rG, ciphertext, err := ecies.
			NewEncryptor(cryptohelpers.AESGCM256Encrypt(kdf)).
			Encrypt(ephemeralKey, publicKey, message)
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %v", err)
		}

		// Write output file
		// Format: [rG length (4 bytes)][rG bytes][ciphertext length (4 bytes)][ciphertext bytes]
		rGBytes := rG.MarshalSEC1(false)
		rGLength := make([]byte, 4)
		binary.BigEndian.PutUint32(rGLength, uint32(len(rGBytes)))
		ciphertextLength := make([]byte, 4)
		binary.BigEndian.PutUint32(ciphertextLength, uint32(len(ciphertext.CipherText)))

		output := append(rGLength, rGBytes...)
		output = append(output, ciphertextLength...)
		output = append(output, ciphertext.CipherText...)
		output = append(output, ciphertext.Nonce...)

		if err := os.WriteFile(outFile, output, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted file: %v", err)
		}

		fmt.Printf("Encrypted file written to %s\n", outFile)
		return nil
	},
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file",
	Long:  `Decrypt a file using ECIES with AES-GCM-256.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		inFile, _ := cmd.Flags().GetString("in")
		outFile, _ := cmd.Flags().GetString("out")
		keyFile, _ := cmd.Flags().GetString("inkey")

		if inFile == "" {
			return fmt.Errorf("input file is required")
		}
		if outFile == "" {
			return fmt.Errorf("output file is required")
		}
		if keyFile == "" {
			return fmt.Errorf("private key file is required")
		}

		// Read private key
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key: %v", err)
		}

		// Parse private key
		privateKey, err := ecc.UnmarshalPEM(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}

		// Read input file
		input, err := os.ReadFile(inFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		// Parse input file
		// Format: [rG length (4 bytes)][rG bytes][ciphertext length (4 bytes)][ciphertext bytes][nonce]
		if len(input) < 8 { // At least 4 bytes for each length
			return fmt.Errorf("invalid input file format")
		}

		rGLength := binary.BigEndian.Uint32(input[:4])
		if len(input) < int(4+rGLength+4) {
			return fmt.Errorf("invalid input file format")
		}

		rGBytes := input[4 : 4+rGLength]
		rG, err := ecc.ParsePublicKeySEC1(rGBytes)
		if err != nil {
			return fmt.Errorf("failed to parse ephemeral public key: %v", err)
		}

		ciphertextLength := binary.BigEndian.Uint32(input[4+rGLength : 8+rGLength])
		if len(input) < int(8+rGLength+ciphertextLength+12) { // 12 bytes for nonce
			return fmt.Errorf("invalid input file format")
		}

		ciphertext := cryptohelpers.AESGCM256Results{
			CipherText: input[8+rGLength : 8+rGLength+ciphertextLength],
			Nonce:      input[8+rGLength+ciphertextLength:],
		}

		// Decrypt message
		kdf := cryptohelpers.HKDF256(sha256.New)
		plaintext, err := ecies.
			NewDecryptor(cryptohelpers.AESGCM256Decrypt(kdf)).
			Decrypt(privateKey, rG, ciphertext)
		if err != nil {
			return fmt.Errorf("failed to decrypt message: %v", err)
		}

		if err := os.WriteFile(outFile, plaintext, 0644); err != nil {
			return fmt.Errorf("failed to write decrypted file: %v", err)
		}

		fmt.Printf("Decrypted file written to %s\n", outFile)
		return nil
	},
}

var ecdhCmd = &cobra.Command{
	Use:   "ecdh",
	Short: "Perform ECDH key exchange",
	Long:  `Generate a shared secret using Elliptic Curve Diffie-Hellman key exchange.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keyFile, _ := cmd.Flags().GetString("inkey")
		peerKeyFile, _ := cmd.Flags().GetString("peerkey")
		outFile, _ := cmd.Flags().GetString("out")

		if keyFile == "" {
			return fmt.Errorf("private key file is required")
		}
		if peerKeyFile == "" {
			return fmt.Errorf("peer public key file is required")
		}
		if outFile == "" {
			return fmt.Errorf("output file is required")
		}

		// Read private key
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key: %v", err)
		}

		// Parse private key
		privateKey, err := ecc.UnmarshalPEM(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}

		// Read peer public key
		peerKeyBytes, err := os.ReadFile(peerKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read peer public key: %v", err)
		}

		// Parse peer public key
		peerPublicKey, err := ecc.UnmarshalPublicPEM(peerKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse peer public key: %v", err)
		}

		// Derive shared secret
		ecdhKey := ecdh.ECDHPrivateKey(privateKey)
		sharedSecret, err := ecdhKey.DeriveSharedSecret(peerPublicKey)
		if err != nil {
			return fmt.Errorf("failed to derive shared secret: %v", err)
		}

		// Write shared secret to output file
		if err := os.WriteFile(outFile, sharedSecret, 0600); err != nil {
			return fmt.Errorf("failed to write shared secret: %v", err)
		}

		fmt.Printf("Shared secret written to %s\n", outFile)
		return nil
	},
}

func init() {
	// Add commands to root
	rootCmd.AddCommand(genpkeyCmd)
	rootCmd.AddCommand(pkeyCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(ecdhCmd)

	// Add flags
	genpkeyCmd.Flags().StringP("out", "o", "", "Output file for private key")
	genpkeyCmd.MarkFlagRequired("out")

	pkeyCmd.Flags().StringP("in", "i", "", "Input file containing private key")
	pkeyCmd.Flags().StringP("out", "o", "", "Output file for public key")
	pkeyCmd.Flags().Bool("pubout", false, "Output public key")
	pkeyCmd.MarkFlagRequired("in")
	pkeyCmd.MarkFlagRequired("out")

	signCmd.Flags().StringP("in", "i", "", "Input file to sign")
	signCmd.Flags().StringP("out", "o", "", "Output file for signature")
	signCmd.Flags().StringP("inkey", "k", "", "Private key file")
	signCmd.MarkFlagRequired("in")
	signCmd.MarkFlagRequired("out")
	signCmd.MarkFlagRequired("inkey")

	verifyCmd.Flags().StringP("in", "i", "", "Input file to verify")
	verifyCmd.Flags().StringP("sigfile", "s", "", "Signature file")
	verifyCmd.Flags().StringP("inkey", "k", "", "Public key file")
	verifyCmd.MarkFlagRequired("in")
	verifyCmd.MarkFlagRequired("sigfile")
	verifyCmd.MarkFlagRequired("inkey")

	encryptCmd.Flags().StringP("in", "i", "", "Input file to encrypt")
	encryptCmd.Flags().StringP("out", "o", "", "Output file for encrypted data")
	encryptCmd.Flags().StringP("inkey", "k", "", "Public key file")
	encryptCmd.MarkFlagRequired("in")
	encryptCmd.MarkFlagRequired("out")
	encryptCmd.MarkFlagRequired("inkey")

	decryptCmd.Flags().StringP("in", "i", "", "Input file to decrypt")
	decryptCmd.Flags().StringP("out", "o", "", "Output file for decrypted data")
	decryptCmd.Flags().StringP("inkey", "k", "", "Private key file")
	decryptCmd.MarkFlagRequired("in")
	decryptCmd.MarkFlagRequired("out")
	decryptCmd.MarkFlagRequired("inkey")

	ecdhCmd.Flags().StringP("inkey", "k", "", "Private key file")
	ecdhCmd.Flags().StringP("peerkey", "p", "", "Peer's public key file")
	ecdhCmd.Flags().StringP("out", "o", "", "Output file for shared secret")
	ecdhCmd.MarkFlagRequired("inkey")
	ecdhCmd.MarkFlagRequired("peerkey")
	ecdhCmd.MarkFlagRequired("out")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
