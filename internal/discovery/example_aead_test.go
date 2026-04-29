package discovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// TestAEADVectorDecrypts is the contract test: the published AEAD
// vector in the discovery doc MUST decrypt to the published plaintext.
// An external implementer who matches every byte we publish gets back
// the original message; if any value drifts (key derivation, AAD
// encoding, nonce handling) this test fails.
func TestAEADVectorDecrypts(t *testing.T) {
	v := exampleAEAD

	// Reproduce the shared secret from published private scalars.
	curve := ecdh.P256()
	alicePriv := mustECDHFromHex(curve, v.AlicePrivHex)
	bobPriv := mustECDHFromHex(curve, v.BobPrivHex)

	sharedFromAlice, err := alicePriv.ECDH(bobPriv.PublicKey())
	if err != nil {
		t.Fatalf("ECDH alice→bob: %v", err)
	}
	if hex.EncodeToString(sharedFromAlice) != v.SharedSecretHex {
		t.Errorf("shared secret drift\ngot:  %s\nwant: %s", hex.EncodeToString(sharedFromAlice), v.SharedSecretHex)
	}
	// Symmetric: bob→alice should match.
	sharedFromBob, err := bobPriv.ECDH(alicePriv.PublicKey())
	if err != nil {
		t.Fatalf("ECDH bob→alice: %v", err)
	}
	if !bytesEqual(sharedFromAlice, sharedFromBob) {
		t.Errorf("ECDH not symmetric — implementation broken")
	}

	// Reproduce the AES key from HKDF.
	salt, _ := hex.DecodeString(v.HKDFSaltHex)
	r := hkdf.New(sha256.New, sharedFromAlice, salt, []byte(v.HKDFInfo))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(r, derived); err != nil {
		t.Fatalf("HKDF: %v", err)
	}
	if hex.EncodeToString(derived) != v.SymKeyHex {
		t.Errorf("derived key drift\ngot:  %s\nwant: %s", hex.EncodeToString(derived), v.SymKeyHex)
	}

	// Reproduce the AAD: utf8(path_id) || utf8(msg_id), no separator.
	expectedAAD := []byte(v.PathID + v.MsgID)
	if hex.EncodeToString(expectedAAD) != v.AADHex {
		t.Errorf("AAD drift\ngot:  %s\nwant: %s", hex.EncodeToString(expectedAAD), v.AADHex)
	}

	// Decrypt the published wire ciphertext (nonce || aead-output) using
	// the published key + AAD. Must yield the published plaintext.
	wireCt, err := hex.DecodeString(v.WireCiphertextHex)
	if err != nil {
		t.Fatalf("decode wire ciphertext: %v", err)
	}
	if len(wireCt) < exampleNonceSize {
		t.Fatalf("wire ciphertext shorter than nonce")
	}
	nonce := wireCt[:exampleNonceSize]
	ctAndTag := wireCt[exampleNonceSize:]

	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatalf("AES.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM.New: %v", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ctAndTag, expectedAAD)
	if err != nil {
		t.Fatalf("AEAD Open failed: %v — vector is broken (key, nonce, AAD, or ciphertext drifted)", err)
	}
	if string(plaintext) != v.Plaintext {
		t.Errorf("decrypted plaintext drift\ngot:  %q\nwant: %q", string(plaintext), v.Plaintext)
	}
}

// TestAEADVectorWrongAADFails — security-critical: changing the AAD
// must invalidate decryption. Pins that the AAD is actually load-bearing
// in our scheme; if someone naively passes nil AAD, decryption MUST fail.
func TestAEADVectorWrongAADFails(t *testing.T) {
	v := exampleAEAD
	derived, _ := hex.DecodeString(v.SymKeyHex)
	wireCt, _ := hex.DecodeString(v.WireCiphertextHex)
	nonce := wireCt[:exampleNonceSize]
	ctAndTag := wireCt[exampleNonceSize:]

	block, _ := aes.NewCipher(derived)
	gcm, _ := cipher.NewGCM(block)

	// Wrong AAD #1: nil (the legacy implementation's mistake)
	if _, err := gcm.Open(nil, nonce, ctAndTag, nil); err == nil {
		t.Errorf("AEAD Open with nil AAD MUST fail — would mean the AAD isn't actually binding")
	}
	// Wrong AAD #2: just path_id, no msg_id
	if _, err := gcm.Open(nil, nonce, ctAndTag, []byte(v.PathID)); err == nil {
		t.Errorf("AEAD Open with partial AAD (path_id only) MUST fail")
	}
	// Wrong AAD #3: order swapped
	swapped := []byte(v.MsgID + v.PathID)
	if _, err := gcm.Open(nil, nonce, ctAndTag, swapped); err == nil {
		t.Errorf("AEAD Open with reversed AAD order MUST fail — pins concatenation order")
	}
}

// TestAEADVectorAADContainsExactBytes pins the AAD's exact byte
// composition: starts with `nxc_`, contains the UUIDv7 dashes, total
// length = len(path_id) + len(msg_id), no whitespace, no separator.
func TestAEADVectorAADContainsExactBytes(t *testing.T) {
	v := exampleAEAD
	aad, _ := hex.DecodeString(v.AADHex)

	if !strings.HasPrefix(string(aad), "nxc_") {
		t.Errorf("AAD must start with `nxc_` (path_id prefix)")
	}
	expectedLen := len(v.PathID) + len(v.MsgID)
	if len(aad) != expectedLen {
		t.Errorf("AAD length drift: got %d, want %d (path_id %d + msg_id %d)",
			len(aad), expectedLen, len(v.PathID), len(v.MsgID))
	}
	// Boundary check: bytes [len(path_id):] should equal msg_id.
	if string(aad[len(v.PathID):]) != v.MsgID {
		t.Errorf("AAD second segment != msg_id")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
