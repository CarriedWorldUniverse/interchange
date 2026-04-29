package discovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// exampleAEAD encapsulates a complete encrypt-and-decrypt-able vector
// for the v1 AAD-binding scheme (path_id || msg_id). The published
// values are deterministic from fixed seeds + a fixed plaintext, so
// any external implementer of the protocol can reproduce them
// byte-for-byte and decrypt the published ciphertext using their own
// AES-256-GCM with the published key/nonce/AAD.
//
// Inputs (all fixed):
//   - alice ECDH P-256 private key (from a fixed seed-derived integer)
//   - bob   ECDH P-256 private key (from a different fixed seed-derived integer)
//   - plaintext: a fixed UTF-8 string
//   - nonce: 12 fixed bytes (0x00..0x0B)
//   - msg_id: a fixed UUIDv7-shaped string
//
// Derived deterministically:
//   - both ECDH public keys (SEC1-uncompressed)
//   - path_id = "nxc_" + b64u(sha256(sort(rawPubA, rawPubB)))
//   - shared secret = ECDH(alice priv, bob pub) — equals ECDH(bob priv, alice pub) by symmetry
//   - sym key = HKDF-SHA256(shared, salt=zero32, info="nexus-casket-channel-v1") → 32 bytes
//   - aad = utf8(path_id) || utf8(msg_id)
//   - ciphertext_with_tag = AES-256-GCM.Seal(plaintext, nonce, aad) under sym key
//   - wire ciphertext = nonce || ciphertext_with_tag
//
// All hex/base64 representations are pre-computed at process start
// and embedded in the discovery doc's examples block, so an external
// implementer reading the well-known doc has every input + every
// expected output in front of them.

const (
	// AEAD alg constants (matching casket-go).
	exampleAEADInfo  = "nexus-casket-channel-v1"
	exampleNonceSize = 12

	exampleAEADPlaintext = `{"origin_nexus":"alice-nexus","dest_nexus":"bob-nexus","kind":"proposal","content_type":"text/markdown","body":"Hello, Bob. This is a test message.","attachments":[]}`
	// Fixed AEAD msg_id — the same one used by the example outer envelope.
	exampleAEADMsgID = "01979b0a-c0de-7eef-a000-000000000001"
	// Fixed nonce for reproducibility — DO NOT reuse in production.
	exampleAEADNonceHex = "000102030405060708090a0b"
	// Fixed P-256 scalars for alice + bob. Using deterministic
	// 32-byte values that pass P-256's "not zero, not n, < n" check.
	exampleAlicePrivHex = "0000000000000000000000000000000000000000000000000000000000000001"
	exampleBobPrivHex   = "0000000000000000000000000000000000000000000000000000000000000002"
)

// AEADExample is the full vector exposed in the discovery doc.
type AEADExample struct {
	Note string `json:"note"`

	AlicePrivHex     string `json:"alice_p256_private_scalar_hex"`
	AlicePubB64u     string `json:"alice_p256_public_sec1_base64url"`
	BobPrivHex       string `json:"bob_p256_private_scalar_hex"`
	BobPubB64u       string `json:"bob_p256_public_sec1_base64url"`
	SharedSecretHex  string `json:"shared_secret_hex_32_bytes"`
	SymKeyHex        string `json:"derived_aes256gcm_key_hex_32_bytes"`
	HKDFInfo         string `json:"hkdf_info_string"`
	HKDFSaltHex      string `json:"hkdf_salt_hex_32_zero_bytes"`

	PathID    string `json:"path_id"`
	MsgID     string `json:"msg_id"`
	AADHex    string `json:"aad_hex_path_id_concat_msg_id_utf8"`
	NonceHex  string `json:"nonce_hex_12_bytes"`
	Plaintext string `json:"plaintext"`

	CiphertextWithTagHex string `json:"ciphertext_with_tag_hex"`
	WireCiphertextHex    string `json:"wire_ciphertext_hex_nonce_then_aead_output"`
	WireCiphertextB64    string `json:"wire_ciphertext_base64url"`
	CiphertextSHA256Hex  string `json:"ciphertext_sha256_hex"`

	VerifyHint string `json:"verify_hint"`
}

var exampleAEAD = computeAEADExample()

func computeAEADExample() AEADExample {
	curve := ecdh.P256()

	alicePriv := mustECDHFromHex(curve, exampleAlicePrivHex)
	bobPriv := mustECDHFromHex(curve, exampleBobPrivHex)

	alicePubBytes := alicePriv.PublicKey().Bytes()
	bobPubBytes := bobPriv.PublicKey().Bytes()

	shared, err := alicePriv.ECDH(bobPriv.PublicKey())
	if err != nil {
		panic(fmt.Sprintf("example AEAD: ECDH: %v", err))
	}

	salt := make([]byte, 32) // 32 zero bytes per casket spec
	r := hkdf.New(sha256.New, shared, salt, []byte(exampleAEADInfo))
	symKey := make([]byte, 32)
	if _, err := io.ReadFull(r, symKey); err != nil {
		panic(fmt.Sprintf("example AEAD: HKDF: %v", err))
	}

	// Derive path_id from raw alice + bob ECDH pubkeys' Ed25519
	// SIGNING pubkeys (path_id is over signing keys, not DH keys).
	// Use the existing alice/bob signing pubkeys derived elsewhere.
	pathID := derivePathID(alicePubB64u, bobPubB64u)

	aad := []byte(pathID + exampleAEADMsgID)

	nonce, err := hex.DecodeString(exampleAEADNonceHex)
	if err != nil || len(nonce) != exampleNonceSize {
		panic("example AEAD: bad nonce hex")
	}

	block, err := aes.NewCipher(symKey)
	if err != nil {
		panic(fmt.Sprintf("example AEAD: AES: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("example AEAD: GCM: %v", err))
	}
	ctWithTag := gcm.Seal(nil, nonce, []byte(exampleAEADPlaintext), aad)

	wireCt := append(append([]byte{}, nonce...), ctWithTag...)
	wireSha := sha256.Sum256(wireCt)

	return AEADExample{
		Note: "Self-contained AEAD vector. An external implementer reproduces this by " +
			"computing ECDH P-256 between the published alice and bob private scalars, " +
			"running HKDF-SHA256 over the shared secret with the published salt + info " +
			"to derive a 32-byte AES-256-GCM key, then encrypting the published plaintext " +
			"with the published 12-byte nonce and AAD = utf8(path_id) || utf8(msg_id). " +
			"The output should match wire_ciphertext_hex byte-for-byte.",

		AlicePrivHex:    exampleAlicePrivHex,
		AlicePubB64u:    base64.RawURLEncoding.EncodeToString(alicePubBytes),
		BobPrivHex:      exampleBobPrivHex,
		BobPubB64u:      base64.RawURLEncoding.EncodeToString(bobPubBytes),
		SharedSecretHex: hex.EncodeToString(shared),
		SymKeyHex:       hex.EncodeToString(symKey),
		HKDFInfo:        exampleAEADInfo,
		HKDFSaltHex:     hex.EncodeToString(salt),

		PathID:    pathID,
		MsgID:     exampleAEADMsgID,
		AADHex:    hex.EncodeToString(aad),
		NonceHex:  exampleAEADNonceHex,
		Plaintext: exampleAEADPlaintext,

		CiphertextWithTagHex: hex.EncodeToString(ctWithTag),
		WireCiphertextHex:    hex.EncodeToString(wireCt),
		WireCiphertextB64:    base64.RawURLEncoding.EncodeToString(wireCt),
		CiphertextSHA256Hex:  hex.EncodeToString(wireSha[:]),

		VerifyHint: "To verify: AES-256-GCM Open(key=derived_aes256gcm_key_hex, " +
			"nonce=nonce_hex, aad=aad_hex, ciphertext+tag=ciphertext_with_tag_hex) " +
			"should return the plaintext byte-for-byte.",
	}
}

// mustECDHFromHex reconstructs an ECDH private key from a fixed scalar
// for reproducibility. The Go stdlib's ecdh package generally expects
// random keys, but allows construction from a known scalar.
func mustECDHFromHex(curve ecdh.Curve, hexStr string) *ecdh.PrivateKey {
	scalar, err := hex.DecodeString(hexStr)
	if err != nil || len(scalar) != 32 {
		panic("example AEAD: bad scalar hex: " + hexStr)
	}
	priv, err := curve.NewPrivateKey(scalar)
	if err != nil {
		panic(fmt.Sprintf("example AEAD: NewPrivateKey: %v", err))
	}
	return priv
}

// _ touches rand to keep the import even if codepath shifts.
var _ = rand.Reader
