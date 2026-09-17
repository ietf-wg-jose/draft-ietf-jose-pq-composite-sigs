package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/schemes"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/sha3"
)

const (
	compositePrefix = "436F6D706F73697465416C676F726974686D5369676E61747572657332303235"
)

type AlgorithmConfig struct {
	Name      string
	Label     string
	COSEAlg   int
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
		COSEAlg:   -54,
		CurveName: "P256",
		TradAlg:   "ECDSA",
		TradHash:  "SHA256",
		PreHash:   "SHA256",
	},
	"ML-DSA-65-ES256": {
		Name:      "ML-DSA-65-ES256",
		Label:     "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
		COSEAlg:   -55,
		CurveName: "P256",
		TradAlg:   "ECDSA",
		TradHash:  "SHA256",
		PreHash:   "SHA512",
	},
	"ML-DSA-87-ES384": {
		Name:      "ML-DSA-87-ES384",
		Label:     "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
		COSEAlg:   -56,
		CurveName: "P384",
		TradAlg:   "ECDSA",
		TradHash:  "SHA384",
		PreHash:   "SHA512",
	},
	"ML-DSA-44-Ed25519": {
		Name:    "ML-DSA-44-Ed25519",
		Label:   "COMPSIG-MLDSA44-Ed25519-SHA512",
		COSEAlg: -57,
		TradAlg: "Ed25519",
		PreHash: "SHA512",
	},
	"ML-DSA-65-Ed25519": {
		Name:    "ML-DSA-65-Ed25519",
		Label:   "COMPSIG-MLDSA65-Ed25519-SHA512",
		COSEAlg: -58,
		TradAlg: "Ed25519",
		PreHash: "SHA512",
	},
	"ML-DSA-87-Ed448": {
		Name:    "ML-DSA-87-Ed448",
		Label:   "COMPSIG-MLDSA87-Ed448-SHAKE256",
		COSEAlg: -59,
		TradAlg: "Ed448",
		PreHash: "SHAKE256",
	},
}

// COSE Key labels
const (
	coseKeyKty  = 1
	coseKeyKid  = 2
	coseKeyAlg  = 3
	coseKeyPub  = -1
	coseKeyPriv = -2
)

// TradKeyPair holds either ECDSA or EdDSA keys
type TradKeyPair struct {
	ECDSAPriv *ecdsa.PrivateKey

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
	parts := strings.SplitN(algName, "-", 4)
	mldsaAlg := strings.Join(parts[:3], "-")

	suite := schemes.ByName(mldsaAlg)
	if suite == nil {
		return nil, fmt.Errorf("unsupported ML-DSA algorithm: %s", mldsaAlg)
	}

	var seed []byte
	if keyMaterial != nil && len(keyMaterial.MLDSASeed) == 32 {
		seed = keyMaterial.MLDSASeed
	} else {
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("failed to generate ML-DSA seed: %w", err)
		}
	}

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
	if keyMaterial != nil && len(keyMaterial.ECDSAPrivKey) > 0 &&
		len(keyMaterial.ECDSAPubKeyX) > 0 && len(keyMaterial.ECDSAPubKeyY) > 0 {
		return createECDSAKeyFromBytes(curveName, keyMaterial.ECDSAPrivKey,
			keyMaterial.ECDSAPubKeyX, keyMaterial.ECDSAPubKeyY)
	}

	curve, err := getCurve(curveName)
	if err != nil {
		return nil, err
	}

	d := big.NewInt(1)
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
	if keyMaterial != nil && len(keyMaterial.EdDSASeed) == ed25519.SeedSize {
		seed = keyMaterial.EdDSASeed
	} else {
		seed = make([]byte, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func generateEd448Key(keyMaterial *KeyMaterial) (ed448.PrivateKey, error) {
	var seed []byte
	if keyMaterial != nil && len(keyMaterial.EdDSASeed) == ed448.SeedSize {
		seed = keyMaterial.EdDSASeed
	} else {
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
// ECDSA DER
// ============================================================================

func derEncodeInt(v []byte) []byte {
	i := 0
	for i < len(v)-1 && v[i] == 0x00 {
		i++
	}
	trimmed := v[i:]
	if trimmed[0]&0x80 != 0 {
		out := make([]byte, 0, len(trimmed)+3)
		out = append(out, 0x02, byte(len(trimmed)+1), 0x00)
		out = append(out, trimmed...)
		return out
	}
	out := make([]byte, 0, len(trimmed)+2)
	out = append(out, 0x02, byte(len(trimmed)))
	out = append(out, trimmed...)
	return out
}

func ecdsaSigToDER(r, s []byte) []byte {
	rDER := derEncodeInt(r)
	sDER := derEncodeInt(s)
	body := make([]byte, 0, len(rDER)+len(sDER))
	body = append(body, rDER...)
	body = append(body, sDER...)
	out := make([]byte, 0, len(body)+2)
	out = append(out, 0x30, byte(len(body)))
	out = append(out, body...)
	return out
}

func ecCurveOID(curveName string) ([]byte, error) {
	switch curveName {
	case "P256":
		return []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}, nil
	case "P384":
		return []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}, nil
	default:
		return nil, fmt.Errorf("unsupported curve for ECPrivateKey: %s", curveName)
	}
}

func ecPrivateKeyToDER(d []byte, curveName string) ([]byte, error) {
	oidField, err := ecCurveOID(curveName)
	if err != nil {
		return nil, err
	}
	version := []byte{0x02, 0x01, 0x01}
	privKeyField := append([]byte{0x04, byte(len(d))}, d...)
	paramsField := append([]byte{0xA0, byte(len(oidField))}, oidField...)

	body := make([]byte, 0, len(version)+len(privKeyField)+len(paramsField))
	body = append(body, version...)
	body = append(body, privKeyField...)
	body = append(body, paramsField...)

	out := make([]byte, 0, len(body)+2)
	out = append(out, 0x30, byte(len(body)))
	out = append(out, body...)
	return out, nil
}

func x962UncompressedPoint(pub *ecdsa.PublicKey) []byte {
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := make([]byte, keySize)
	yBytes := make([]byte, keySize)
	pub.X.FillBytes(xBytes)
	pub.Y.FillBytes(yBytes)
	out := make([]byte, 0, 1+2*keySize)
	out = append(out, 0x04)
	out = append(out, xBytes...)
	out = append(out, yBytes...)
	return out
}

func curveNameFor(curve elliptic.Curve) (string, error) {
	switch curve {
	case elliptic.P256():
		return "P256", nil
	case elliptic.P384():
		return "P384", nil
	default:
		return "", fmt.Errorf("unsupported curve for DER encoding")
	}
}

// ============================================================================
// Composite Key Generation
// ============================================================================

func GenerateCompositeKey(config AlgorithmConfig, keyMaterial *KeyMaterial) (map[interface{}]interface{}, *MLDSAKeyPair, *TradKeyPair, error) {
	mldsaKeys, err := generateMLDSAKey(config.Name, keyMaterial)
	if err != nil {
		return nil, nil, nil, err
	}

	tradKeys, err := generateTraditionalKey(config, keyMaterial)
	if err != nil {
		return nil, nil, nil, err
	}

	pubBytesMLDSA, err := mldsaKeys.PublicKey.MarshalBinary()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal ML-DSA public key: %w", err)
	}

	pubBytes := buildCompositePublicKey(pubBytesMLDSA, tradKeys, config.TradAlg)
	privBytes, err := buildCompositePrivateKey(mldsaKeys.Seed, tradKeys, config.TradAlg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to build composite private key: %w", err)
	}

	hash := sha256.Sum256(pubBytes)
	kid := hash[:8]

	coseKey := map[interface{}]interface{}{
		coseKeyKty:  7, // AKP key type
		coseKeyKid:  kid,
		coseKeyAlg:  config.COSEAlg,
		coseKeyPub:  pubBytes,
		coseKeyPriv: privBytes,
	}

	return coseKey, mldsaKeys, tradKeys, nil
}

func buildCompositePublicKey(mldsaPubKey []byte, tradKeys *TradKeyPair, tradAlg string) []byte {
	pubBytes := make([]byte, len(mldsaPubKey))
	copy(pubBytes, mldsaPubKey)

	switch tradAlg {
	case "ECDSA":
		pubBytes = append(pubBytes, x962UncompressedPoint(&tradKeys.ECDSAPriv.PublicKey)...)
	case "Ed25519":
		pubBytes = append(pubBytes, tradKeys.Ed25519Priv.Public().(ed25519.PublicKey)...)
	case "Ed448":
		pubBytes = append(pubBytes, tradKeys.Ed448Priv.Public().(ed448.PublicKey)...)
	}

	return pubBytes
}

func buildCompositePrivateKey(mldsaSeed []byte, tradKeys *TradKeyPair, tradAlg string) ([]byte, error) {
	privBytes := make([]byte, len(mldsaSeed))
	copy(privBytes, mldsaSeed)

	switch tradAlg {
	case "ECDSA":
		curve := tradKeys.ECDSAPriv.Curve
		keySize := (curve.Params().BitSize + 7) / 8
		dBytes := make([]byte, keySize)
		tradKeys.ECDSAPriv.D.FillBytes(dBytes)

		curveName, err := curveNameFor(curve)
		if err != nil {
			return nil, err
		}
		ecPrivDER, err := ecPrivateKeyToDER(dBytes, curveName)
		if err != nil {
			return nil, fmt.Errorf("failed to build ECPrivateKey: %w", err)
		}
		privBytes = append(privBytes, ecPrivDER...)
	case "Ed25519":
		privBytes = append(privBytes, tradKeys.Ed25519Priv.Seed()...)
	case "Ed448":
		privBytes = append(privBytes, []byte(tradKeys.Ed448Priv)[:ed448.SeedSize]...)
	}

	return privBytes, nil
}

// ============================================================================
// COSE Sign1 Signature
// ============================================================================

func CreateCOSESign1(config AlgorithmConfig, coseKey map[interface{}]interface{}, mldsaKeys *MLDSAKeyPair, tradKeys *TradKeyPair, payload []byte) ([]byte, []byte, []byte, []byte, error) {

	protectedHeader := map[interface{}]interface{}{
		1: config.COSEAlg,      // alg
		4: coseKey[coseKeyKid], // kid
	}

	protectedHeaderBytes, err := cbor.Marshal(protectedHeader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal protected header: %w", err)
	}

	sigStructure := []interface{}{
		"Signature1",
		protectedHeaderBytes,
		[]byte{},
		payload,
	}

	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal Sig_structure: %w", err)
	}

	prehash, err := computeHash(sigStructureBytes, config.PreHash)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	toBeSigned := buildMessageToBeSigned(config.Label, prehash)

	sigMLDSA, err := signMLDSA(mldsaKeys.PrivateKey, toBeSigned, config.Label)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sigTrad, err := signTraditional(tradKeys, toBeSigned, config)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	signature := append(sigMLDSA, sigTrad...)

	coseSign1 := []interface{}{
		protectedHeaderBytes,
		map[interface{}]interface{}{},
		payload,
		signature,
	}

	coseSign1Bytes, err := cbor.Marshal(cbor.Tag{Number: 18, Content: coseSign1})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal COSE_Sign1: %w", err)
	}

	return coseSign1Bytes, sigStructureBytes, toBeSigned, signature, nil
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

	keySize := (privKey.Curve.Params().BitSize + 7) / 8
	rBytes := make([]byte, keySize)
	sBytes := make([]byte, keySize)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)

	return ecdsaSigToDER(rBytes, sBytes), nil
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
// CBOR Extended Diagnostic Notation rendering
// ============================================================================

const ednBytesPerLine = 32 // 64 hex chars per line

func wrapHex(data []byte, indent string) string {
	h := hex.EncodeToString(data)
	lineLen := ednBytesPerLine * 2
	if len(h) <= lineLen {
		return "h'" + h + "'"
	}
	var b strings.Builder
	b.WriteString("h'")
	for i := 0; i < len(h); i += lineLen {
		end := i + lineLen
		if end > len(h) {
			end = len(h)
		}
		if i > 0 {
			b.WriteString("\n")
			b.WriteString(indent)
		}
		b.WriteString(h[i:end])
	}
	b.WriteString("'")
	return b.String()
}

func algLabel(config AlgorithmConfig) string {
	return config.Name
}

const ednCommentWidth = 26

func ednField(comment string) string {
	c := "/ " + comment + " /"
	if len(c) < ednCommentWidth {
		c += strings.Repeat(" ", ednCommentWidth-len(c))
	} else {
		c += " "
	}
	return c
}

func renderProtectedHeader(config AlgorithmConfig, kid []byte) string {
	return fmt.Sprintf("{\n"+
		"    %s 1: %d,\n"+
		"    %s 4: %s\n"+
		"  }",
		ednField("alg "+algLabel(config)), config.COSEAlg,
		ednField("kid"), wrapHex(kid, "  "))
}

func renderCOSEKey(config AlgorithmConfig, kid, pub, priv []byte) string {
	var b strings.Builder
	b.WriteString("{\n")
	fmt.Fprintf(&b, "  %s 1: 7,\n", ednField("kty AKP"))
	fmt.Fprintf(&b, "  %s 3: %d,\n", ednField("alg "+config.Name), config.COSEAlg)
	fmt.Fprintf(&b, "  %s 2: %s,\n", ednField("kid"), wrapHex(kid, "  "))
	fmt.Fprintf(&b, "  %s -1:\n%s,\n", ednField("public key"), wrapHex(pub, "  "))
	fmt.Fprintf(&b, "  %s -2:\n%s\n", ednField("private key"), wrapHex(priv, "  "))
	b.WriteString("}")
	return b.String()
}

func renderSigStructure(config AlgorithmConfig, kid, payload []byte) string {
	var b strings.Builder
	b.WriteString("[\n")
	b.WriteString("  \"Signature1\",\n")
	fmt.Fprintf(&b, "  << %s >>,\n", renderProtectedHeader(config, kid))
	b.WriteString("  / external_aad / h'',\n")
	fmt.Fprintf(&b, "  / payload /\n  %s\n", wrapHex(payload, "  "))
	b.WriteString("]")
	return b.String()
}

func renderCOSESign1(config AlgorithmConfig, kid, payload, signature []byte) string {
	var b strings.Builder
	b.WriteString("18([\n")
	fmt.Fprintf(&b, "  << %s >>,\n", renderProtectedHeader(config, kid))
	b.WriteString("  / unprotected / {},\n")
	fmt.Fprintf(&b, "  / payload /\n  %s,\n", wrapHex(payload, "  "))
	fmt.Fprintf(&b, "  / signature /\n  %s\n", wrapHex(signature, "  "))
	b.WriteString("])")
	return b.String()
}

// ============================================================================
// Main
// ============================================================================

func main() {
	algName := flag.String("alg", "ML-DSA-87-ES384", "Composite algorithm name")
	mldsaSeedHex := flag.String("mldsa-seed", "", "ML-DSA seed (32 bytes in hex, optional)")
	ecdsaPrivHex := flag.String("ecdsa-priv", "", "ECDSA private key d (hex, optional)")
	ecdsaPubXHex := flag.String("ecdsa-pubx", "", "ECDSA public key X (hex, optional)")
	ecdsaPubYHex := flag.String("ecdsa-puby", "", "ECDSA public key Y (hex, optional)")
	eddsaSeedHex := flag.String("eddsa-seed", "", "EdDSA seed (32 bytes for Ed25519, 57 for Ed448, hex, optional)")
	payloadStr := flag.String("payload", "hello post quantum signatures", "Payload to sign")

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

	coseKey, mldsaKeys, tradKeys, err := GenerateCompositeKey(config, keyMaterial)
	if err != nil {
		log.Fatalf("Key generation failed: %v", err)
	}

	payload := []byte(*payloadStr)
	coseSign1Bytes, sigStructureBytes, toBeSigned, signature, err := CreateCOSESign1(config, coseKey, mldsaKeys, tradKeys, payload)
	if err != nil {
		log.Fatalf("Signature failed: %v", err)
	}
	_ = coseSign1Bytes

	kid := coseKey[coseKeyKid].([]byte)
	pub := coseKey[coseKeyPub].([]byte)
	priv := coseKey[coseKeyPriv].([]byte)

	fmt.Printf("/ ML-DSA seed (32 bytes) /\n%s\n\n", wrapHex(mldsaKeys.Seed, ""))

	switch config.TradAlg {
	case "ECDSA":
		curve := tradKeys.ECDSAPriv.Curve
		keySize := (curve.Params().BitSize + 7) / 8
		dBytes := make([]byte, keySize)
		tradKeys.ECDSAPriv.D.FillBytes(dBytes)
		fmt.Printf("/ ECDSA private key d (%d bytes) /\n%s\n\n", keySize, wrapHex(dBytes, ""))
	case "Ed25519":
		fmt.Printf("/ Ed25519 seed (32 bytes) /\n%s\n\n", wrapHex(tradKeys.Ed25519Priv.Seed(), ""))
	case "Ed448":
		fmt.Printf("/ Ed448 seed (57 bytes) /\n%s\n\n", wrapHex([]byte(tradKeys.Ed448Priv)[:ed448.SeedSize], ""))
	}

	fmt.Printf("/ AKP COSE_Key /\n%s\n\n", renderCOSEKey(config, kid, pub, priv))

	fmt.Printf("/ Sig_structure (M) /\n%s\n\n", renderSigStructure(config, kid, payload))

	fmt.Printf("/ Message representative M' = Prefix || Label || 0x00 || PH(M) /\n%s\n\n", wrapHex(toBeSigned, ""))

	fmt.Printf("/ COSE_Sign1 /\n%s\n", renderCOSESign1(config, kid, payload, signature))

	_ = sigStructureBytes
}
