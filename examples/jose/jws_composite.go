package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"log"
	"math/big"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/schemes"
	"golang.org/x/crypto/sha3"
)

const (
	compositePrefix = "436F6D706F73697465416C676F726974686D5369676E61747572657332303235"
)

type AlgorithmConfig struct {
	Name      string
	Label     string
	CurveName string // For ECDSA variants (empty for EdDSA)
	TradAlg   string // "ECDSA" or "EdDSA"
	TradHash  string // Hash algorithm for ECDSA signing
	PreHash   string // Pre-hash algorithm
}

// KeyMaterial contains optional key material for deterministic key generation
type KeyMaterial struct {
	MLDSASeed    []byte // 32 bytes seed
	ECDSAPrivKey []byte // Private key d for ECDSA
	ECDSAPubKeyX []byte // Public key X for ECDSA
	ECDSAPubKeyY []byte // Public key Y for ECDSA
	EdDSASeed    []byte // Seed for EdDSA (32 bytes for Ed25519, 57 bytes for Ed448)
}


var algorithms = map[string]AlgorithmConfig{
	"ML-DSA-44-ES256": {
		Name:      "ML-DSA-44-ES256",
		Label:     "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
		CurveName: "P256",
		TradAlg:   "ECDSA",
		TradHash:  "SHA256",
		PreHash:   "SHA256",
	},
	"ML-DSA-65-ES256": {
		Name:      "ML-DSA-65-ES256",
		Label:     "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
		CurveName: "P256",
		TradAlg:   "ECDSA",
		TradHash:  "SHA256",
		PreHash:   "SHA512",
	},
	"ML-DSA-87-ES384": {
		Name:      "ML-DSA-87-ES384",
		Label:     "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
		CurveName: "P384",
		TradAlg:   "ECDSA",
		TradHash:  "SHA384",
		PreHash:   "SHA512",
	},
	"ML-DSA-44-Ed25519": {
		Name:    "ML-DSA-44-Ed25519",
		Label:   "COMPSIG-MLDSA44-Ed25519-SHA512",
		TradAlg: "Ed25519",
		PreHash: "SHA512",
	},
	"ML-DSA-65-Ed25519": {
		Name:    "ML-DSA-65-Ed25519",
		Label:   "COMPSIG-MLDSA65-Ed25519-SHA512",
		TradAlg: "Ed25519",
		PreHash: "SHA512",
	},
	"ML-DSA-87-Ed448": {
		Name:    "ML-DSA-87-Ed448",
		Label:   "COMPSIG-MLDSA87-Ed448-SHAKE256",
		TradAlg: "Ed448",
		PreHash: "SHAKE256",
	},
}

type JWSHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type AKPKey struct {
	Kid  string `json:"kid,omitempty"`
	Kty  string `json:"kty"`
	Alg  string `json:"alg"`
	Pub  string `json:"pub"`
	Priv string `json:"priv,omitempty"`
}

type TestVector struct {
	MLDSASeed             string `json:"mldsa_seed"`
	ECDSAD                string `json:"ecdsa_d,omitempty"`
	EdDSASeed             string `json:"eddsa_seed,omitempty"`
	JWK                   AKPKey `json:"jwk"`
	JWS                   string `json:"jws"`
	RawToBeSigned         string `json:"raw_to_be_signed"`
	RawCompositeSignature string `json:"raw_composite_signature"`
	RawCompositePublicKey string `json:"raw_composite_public_key"`
}

// TradKeyPair holds either ECDSA or EdDSA keys
type TradKeyPair struct {
	ECDSAPriv   *ecdsa.PrivateKey

	Ed25519Priv ed25519.PrivateKey
	Ed448Priv   ed448.PrivateKey
}

// MLDSAKeyPair holds ML-DSA keys
type MLDSAKeyPair struct {
	PublicKey  sign.PublicKey
	PrivateKey sign.PrivateKey
	Seed       []byte
}

// ============================================================================
// ML-DSA Key Generation
// ============================================================================

func generateMLDSAKey(algName string, keyMaterial *KeyMaterial) (*MLDSAKeyPair, error) {
	// Extract ML-DSA algorithm name
	parts := strings.SplitN(algName, "-", 4)
	mldsaAlg := strings.Join(parts[:3], "-")

	suite := schemes.ByName(mldsaAlg)
	if suite == nil {
		return nil, fmt.Errorf("unsupported ML-DSA algorithm: %s", mldsaAlg)
	}

	// Use provided seed or generate random one
	var seed []byte
	if keyMaterial != nil && len(keyMaterial.MLDSASeed) == 32 {
		seed = keyMaterial.MLDSASeed
	} else {
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("failed to generate ML-DSA seed: %w", err)
		}
	}

	// Generate key pair from seed
	pubKey, privKey := suite.DeriveKey(seed)

	return &MLDSAKeyPair{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Seed:       seed,
	}, nil
}

// ============================================================================
// Traditional (ECDSA/EdDSA) Key Generation
// ============================================================================

func generateECDSAKey(curveName string, keyMaterial *KeyMaterial) (*ecdsa.PrivateKey, error) {
	// If full key material is provided, use it
	if keyMaterial != nil && len(keyMaterial.ECDSAPrivKey) > 0 &&
		len(keyMaterial.ECDSAPubKeyX) > 0 && len(keyMaterial.ECDSAPubKeyY) > 0 {
		return createECDSAKeyFromBytes(curveName, keyMaterial.ECDSAPrivKey,
			keyMaterial.ECDSAPubKeyX, keyMaterial.ECDSAPubKeyY)
	}

	// Generate deterministic key from zero value
	curve, err := getCurve(curveName)
	if err != nil {
		return nil, err
	}

	// For deterministic test vectors, use d = 1
	d := big.NewInt(1)
	
	// Compute public key
	x, y := curve.ScalarBaseMult(d.Bytes())
	
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}
	
	return privKey, nil
}

func generateEd25519Key(keyMaterial *KeyMaterial) (ed25519.PrivateKey, error) {
	var seed []byte
	
	// If seed is provided, use it
	if keyMaterial != nil && len(keyMaterial.EdDSASeed) == ed25519.SeedSize {
		seed = keyMaterial.EdDSASeed
	} else {
		// Use zero seed for deterministic generation
		seed = make([]byte, ed25519.SeedSize)
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

func generateEd448Key(keyMaterial *KeyMaterial) (ed448.PrivateKey, error) {
	var seed []byte
	
	// If seed is provided, use it
	if keyMaterial != nil && len(keyMaterial.EdDSASeed) == ed448.SeedSize {
		seed = keyMaterial.EdDSASeed
	} else {
		// Use zero seed for deterministic generation
		seed = make([]byte, ed448.SeedSize)
	}

	return ed448.NewKeyFromSeed(seed), nil
}

func generateTraditionalKey(config AlgorithmConfig, keyMaterial *KeyMaterial) (*TradKeyPair, error) {
	tradKeys := &TradKeyPair{}
	var err error

	switch config.TradAlg {
	case "ECDSA":
		tradKeys.ECDSAPriv, err = generateECDSAKey(config.CurveName, keyMaterial)
	case "Ed25519":
		tradKeys.Ed25519Priv, err = generateEd25519Key(keyMaterial)
	case "Ed448":
		tradKeys.Ed448Priv, err = generateEd448Key(keyMaterial)
	default:
		return nil, fmt.Errorf("unsupported traditional algorithm: %s", config.TradAlg)
	}

	return tradKeys, err
}

// ============================================================================
// Composite Key Generation
// ============================================================================

func GenerateCompositeKey(config AlgorithmConfig, keyMaterial *KeyMaterial) (*AKPKey, *MLDSAKeyPair, *TradKeyPair, error) {
	// Generate ML-DSA key
	mldsaKeys, err := generateMLDSAKey(config.Name, keyMaterial)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate traditional key
	tradKeys, err := generateTraditionalKey(config, keyMaterial)
	if err != nil {
		return nil, nil, nil, err
	}

	// Serialize ML-DSA public key
	pubBytesMLDSA, err := mldsaKeys.PublicKey.MarshalBinary()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal ML-DSA public key: %w", err)
	}


	pubBytes := buildCompositePublicKey(pubBytesMLDSA, tradKeys, config.TradAlg)
	privBytes := buildCompositePrivateKey(mldsaKeys.Seed, tradKeys, config.TradAlg)

	jwk := &AKPKey{
		Kty:  "AKP",
		Alg:  config.Name,
		Pub:  base64.RawURLEncoding.EncodeToString(pubBytes),
		Priv: base64.RawURLEncoding.EncodeToString(privBytes),
	}

	jwkJSON, _ := json.Marshal(jwk)
	kid, err := calculateJWKThumbprint(string(jwkJSON))
	if err != nil {
		return nil, nil, nil, err
	}
	jwk.Kid = kid

	return jwk, mldsaKeys, tradKeys, nil
}

func buildCompositePublicKey(mldsaPubKey []byte, tradKeys *TradKeyPair, tradAlg string) []byte {
	pubBytes := make([]byte, len(mldsaPubKey))
	copy(pubBytes, mldsaPubKey)

	switch tradAlg {
	case "ECDSA":
		pubBytes = append(pubBytes, tradKeys.ECDSAPriv.PublicKey.X.Bytes()...)
		pubBytes = append(pubBytes, tradKeys.ECDSAPriv.PublicKey.Y.Bytes()...)
	case "Ed25519":
		pubBytes = append(pubBytes, tradKeys.Ed25519Priv.Public().(ed25519.PublicKey)...)
	case "Ed448":
		pubBytes = append(pubBytes, tradKeys.Ed448Priv.Public().(ed448.PublicKey)...)
	}

	return pubBytes
}

func buildCompositePrivateKey(mldsaSeed []byte, tradKeys *TradKeyPair, tradAlg string) []byte {
	privBytes := make([]byte, len(mldsaSeed))
	copy(privBytes, mldsaSeed)

	switch tradAlg {
	case "ECDSA":
		// Append ECDSA private key d (padded to curve size)
		curve := tradKeys.ECDSAPriv.Curve
		keySize := (curve.Params().BitSize + 7) / 8 // Round up to nearest byte
		dBytes := tradKeys.ECDSAPriv.D.Bytes()
		paddedD := make([]byte, keySize)
		copy(paddedD[keySize-len(dBytes):], dBytes)
		privBytes = append(privBytes, paddedD...)
	case "Ed25519":
		privBytes = append(privBytes, tradKeys.Ed25519Priv.Seed()...)
	case "Ed448":
		// Ed448 private key: extract only the seed (first 57 bytes)
		privBytes = append(privBytes, []byte(tradKeys.Ed448Priv)[:ed448.SeedSize]...)
	}

	return privBytes
}

// ============================================================================
// Composite Signature
// ============================================================================

func CompactSignComposite(config AlgorithmConfig, jwk *AKPKey, mldsaKeys *MLDSAKeyPair, tradKeys *TradKeyPair, payload []byte) (string, []byte, []byte, error) {
	header := JWSHeader{
		Alg: config.Name,
		Kid: jwk.Kid,
	}
	headerJSON, _ := json.Marshal(header)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	M := []byte(headerB64 + "." + payloadB64)

	prehash, err := computeHash(M, config.PreHash)
	if err != nil {
		return "", nil, nil, err
	}

	toBeSigned := buildMessageToBeSigned(config.Label, prehash)

	// Sign with ML-DSA
	sigMLDSA, err := signMLDSA(mldsaKeys.PrivateKey, toBeSigned, config.Label)
	if err != nil {
		return "", nil, nil, err
	}

	// Sign with traditional algorithm
	sigTrad, err := signTraditional(tradKeys, toBeSigned, config)
	if err != nil {
		return "", nil, nil, err
	}

	// Create composite signature
	sigComposite := append(sigMLDSA, sigTrad...)
	sigB64 := base64.RawURLEncoding.EncodeToString(sigComposite)

	// Final JWS
	jws := headerB64 + "." + payloadB64 + "." + sigB64

	return jws, toBeSigned, sigComposite, nil
}

func buildMessageToBeSigned(label string, prehash []byte) []byte {
	prefix, _ := hex.DecodeString(compositePrefix)
	labelBytes := []byte(label)

	toBeSigned := append(prefix, labelBytes...)
	toBeSigned = append(toBeSigned, 0x00)
	toBeSigned = append(toBeSigned, prehash...)

	return toBeSigned
}

func signMLDSA(privKey sign.PrivateKey, message []byte, context string) ([]byte, error) {
	opts := &sign.SignatureOpts{
		Context: context,
	}

	scheme := privKey.Scheme()
	return scheme.Sign(privKey, message, opts), nil
}

func signTraditional(tradKeys *TradKeyPair, message []byte, config AlgorithmConfig) ([]byte, error) {
	switch config.TradAlg {
	case "ECDSA":
		return signECDSA(tradKeys.ECDSAPriv, message, config.TradHash)
	case "Ed25519":
		return ed25519.Sign(tradKeys.Ed25519Priv, message), nil
	case "Ed448":
		return ed448.Sign(tradKeys.Ed448Priv, message, ""), nil
	default:
		return nil, fmt.Errorf("unsupported traditional algorithm: %s", config.TradAlg)
	}
}

func signECDSA(privKey *ecdsa.PrivateKey, message []byte, hashAlg string) ([]byte, error) {
	hash, err := computeHash(message, hashAlg)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func createECDSAKeyFromBytes(curveName string, privKeyBytes, pubKeyXBytes, pubKeyYBytes []byte) (*ecdsa.PrivateKey, error) {
	curve, err := getCurve(curveName)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(pubKeyXBytes),
			Y:     new(big.Int).SetBytes(pubKeyYBytes),
		},
		D: new(big.Int).SetBytes(privKeyBytes),
	}, nil
}

func getCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P256":
		return elliptic.P256(), nil
	case "P384":
		return elliptic.P384(), nil
	case "P521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

func computeHash(data []byte, hashName string) ([]byte, error) {
	switch hashName {
	case "SHA256":
		h := sha256.Sum256(data)
		return h[:], nil
	case "SHA384":
		h := sha512.Sum384(data)
		return h[:], nil
	case "SHA512":
		h := sha512.Sum512(data)
		return h[:], nil
	case "SHAKE256":

		shake := sha3.NewShake256()
		shake.Write(data)
		output := make([]byte, 64)
		shake.Read(output)
		return output, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashName)
	}
}

func calculateJWKThumbprint(jwkJSON string) (string, error) {
	var key map[string]string
	if err := json.Unmarshal([]byte(jwkJSON), &key); err != nil {
		return "", fmt.Errorf("failed to parse JWK: %w", err)
	}

	var h hash.Hash = sha256.New()

	switch kty := key["kty"]; kty {
	case "EC":
		h.Write([]byte(fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
			key["crv"], key["kty"], key["x"], key["y"])))
	case "AKP":
		h.Write([]byte(fmt.Sprintf(`{"alg":"%s","kty":"%s","pub":"%s"}`,
			key["alg"], key["kty"], key["pub"])))
	default:
		return "", errors.New("unknown JWK key type (kty)")
	}

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func parseHexSeed(seedHex string, expectedLen int) ([]byte, error) {
	if seedHex == "" {
		return nil, nil
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	if len(seed) != expectedLen {
		return nil, fmt.Errorf("invalid seed length: got %d, want %d", len(seed), expectedLen)
	}
	return seed, nil
}

// ============================================================================
// Main
// ============================================================================

func main() {
	// Command-line flags
	algName := flag.String("alg", "ML-DSA-87-ES384", "Composite algorithm name")
	mldsaSeedHex := flag.String("mldsa-seed", "", "ML-DSA seed (32 bytes in hex, optional)")
	ecdsaPrivHex := flag.String("ecdsa-priv", "", "ECDSA private key d (hex, optional)")
	ecdsaPubXHex := flag.String("ecdsa-pubx", "", "ECDSA public key X (hex, optional)")
	ecdsaPubYHex := flag.String("ecdsa-puby", "", "ECDSA public key Y (hex, optional)")
	eddsaSeedHex := flag.String("eddsa-seed", "", "EdDSA seed (32 bytes for Ed25519, 57 for Ed448, hex, optional)")
	payloadStr := flag.String("payload", "It's a dangerous business, Frodo, going out your door.", "Payload to sign")

	flag.Parse()


	config, ok := algorithms[*algName]
	if !ok {
		log.Fatalf("Unknown algorithm: %s", *algName)
	}


	keyMaterial := &KeyMaterial{}
	var err error

	if *mldsaSeedHex != "" {
		keyMaterial.MLDSASeed, err = parseHexSeed(*mldsaSeedHex, 32)
		if err != nil {
			log.Fatalf("Invalid ML-DSA seed: %v", err)
		}
	} else {
		keyMaterial.MLDSASeed = make([]byte, 32)
	}

	if config.TradAlg == "ECDSA" {
		if *ecdsaPrivHex != "" || *ecdsaPubXHex != "" || *ecdsaPubYHex != "" {
			if *ecdsaPrivHex == "" || *ecdsaPubXHex == "" || *ecdsaPubYHex == "" {
				log.Fatalf("ECDSA requires all three: -ecdsa-priv, -ecdsa-pubx, -ecdsa-puby")
			}
			keyMaterial.ECDSAPrivKey, err = hex.DecodeString(*ecdsaPrivHex)
			if err != nil {
				log.Fatalf("Invalid ECDSA private key: %v", err)
			}
			keyMaterial.ECDSAPubKeyX, err = hex.DecodeString(*ecdsaPubXHex)
			if err != nil {
				log.Fatalf("Invalid ECDSA public key X: %v", err)
			}
			keyMaterial.ECDSAPubKeyY, err = hex.DecodeString(*ecdsaPubYHex)
			if err != nil {
				log.Fatalf("Invalid ECDSA public key Y: %v", err)
			}
		}
	}

	if config.TradAlg == "Ed25519" || config.TradAlg == "Ed448" {
		expectedLen := ed25519.SeedSize
		if config.TradAlg == "Ed448" {
			expectedLen = ed448.SeedSize
		}
		if *eddsaSeedHex != "" {
			keyMaterial.EdDSASeed, err = parseHexSeed(*eddsaSeedHex, expectedLen)
			if err != nil {
				log.Fatalf("Invalid EdDSA seed: %v", err)
			}
		}
	}

	jwk, mldsaKeys, tradKeys, err := GenerateCompositeKey(config, keyMaterial)
	if err != nil {
		log.Fatalf("Key generation failed: %v", err)
	}

	payload := []byte(*payloadStr)
	jws, toBeSigned, sigComposite, err := CompactSignComposite(config, jwk, mldsaKeys, tradKeys, payload)
	if err != nil {
		log.Fatalf("Signature failed: %v", err)
	}

	pubKeyBytes, _ := base64.RawURLEncoding.DecodeString(jwk.Pub)

	testVector := TestVector{
		MLDSASeed:             hex.EncodeToString(mldsaKeys.Seed),
		JWK:                   *jwk,
		JWS:                   jws,
		RawToBeSigned:         hex.EncodeToString(toBeSigned),
		RawCompositeSignature: hex.EncodeToString(sigComposite),
		RawCompositePublicKey: hex.EncodeToString(pubKeyBytes),
	}

	switch config.TradAlg {
	case "ECDSA":
		curve := tradKeys.ECDSAPriv.Curve
		keySize := (curve.Params().BitSize + 7) / 8
		dBytes := make([]byte, keySize)
		dBytesActual := tradKeys.ECDSAPriv.D.Bytes()
		copy(dBytes[keySize-len(dBytesActual):], dBytesActual)
		testVector.ECDSAD = hex.EncodeToString(dBytes)
	case "Ed25519":
		testVector.EdDSASeed = hex.EncodeToString(tradKeys.Ed25519Priv.Seed())
	case "Ed448":
		testVector.EdDSASeed = hex.EncodeToString([]byte(tradKeys.Ed448Priv)[:ed448.SeedSize])
	}

	output, err := json.MarshalIndent(testVector, "", "  ")
	if err != nil {
		log.Fatalf("JSON marshaling failed: %v", err)
	}

	fmt.Println(string(output))
}