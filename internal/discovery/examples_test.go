package discovery

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// These tests double as the contract: an external implementer who
// reproduces the steps below MUST get the same byte values that appear
// in the discovery doc. If any of these break, the doc is wrong (or
// the implementation drifted) — fix one or the other.

func TestExampleAlicePubkeyDerivation(t *testing.T) {
	seed, _ := hex.DecodeString(aliceSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	got := base64.RawURLEncoding.EncodeToString(pub)
	if got != alicePubB64u {
		t.Errorf("alice pubkey derivation drifted: got %s want %s", got, alicePubB64u)
	}
	// Document this — RFC 8032 ed25519: pubkey is deterministic from seed.
	// External implementer should get identical output from any compliant
	// Ed25519 implementation.
}

func TestExampleSelfSigPreimageV1Shape(t *testing.T) {
	want := strings.Join([]string{
		"v1",
		"alice-nexus",
		"ed25519",
		alicePubB64u,
		"https://alice.example.org:10000",
		"AAECAwQFBgcICQoLDA0ODw",
		"2026-04-30T00:00:00Z",
	}, "\n")
	if examplePreimageV1 != want {
		t.Errorf("v1 preimage drift\ngot:  %q\nwant: %q", examplePreimageV1, want)
	}
	if strings.Contains(examplePreimageV1, "\r") {
		t.Errorf("v1 preimage contains CR — must be LF only")
	}
	if strings.HasSuffix(examplePreimageV1, "\n") {
		t.Errorf("v1 preimage has trailing LF — spec says no trailing newline")
	}
}

func TestExampleSelfSigPreimageV2Shape(t *testing.T) {
	// v2 adds dh_alg + dh_pubkey to the signed payload, between pubkey
	// and endpoint, so substitution attacks on the ECDH key fail
	// signature verification.
	want := strings.Join([]string{
		"v2",
		"alice-nexus",
		"ed25519",
		alicePubB64u,
		"P-256",
		exampleAliceDhPubB64u,
		"https://alice.example.org:10000",
		"AAECAwQFBgcICQoLDA0ODw",
		"2026-04-30T00:00:00Z",
	}, "\n")
	if examplePreimageV2 != want {
		t.Errorf("v2 preimage drift\ngot:  %q\nwant: %q", examplePreimageV2, want)
	}
	if strings.Contains(examplePreimageV2, "\r") {
		t.Errorf("v2 preimage contains CR — must be LF only")
	}
	if strings.HasSuffix(examplePreimageV2, "\n") {
		t.Errorf("v2 preimage has trailing LF — spec says no trailing newline")
	}
}

func TestExampleSelfSigV1Verifies(t *testing.T) {
	seed, _ := hex.DecodeString(aliceSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	sig, err := base64.RawURLEncoding.DecodeString(examplePreimageSigV1)
	if err != nil {
		t.Fatalf("base64 decode v1: %v", err)
	}
	if !ed25519.Verify(pub, []byte(examplePreimageV1), sig) {
		t.Errorf("v1 self-sig does not verify against alice pubkey + v1 preimage — example is broken")
	}
}

func TestExampleSelfSigV2Verifies(t *testing.T) {
	seed, _ := hex.DecodeString(aliceSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	sig, err := base64.RawURLEncoding.DecodeString(examplePreimageSigV2)
	if err != nil {
		t.Fatalf("base64 decode v2: %v", err)
	}
	if !ed25519.Verify(pub, []byte(examplePreimageV2), sig) {
		t.Errorf("v2 self-sig does not verify against alice pubkey + v2 preimage — example is broken")
	}
}

func TestExamplePathIDFormula(t *testing.T) {
	a, _ := base64.RawURLEncoding.DecodeString(alicePubB64u)
	b, _ := base64.RawURLEncoding.DecodeString(bobPubB64u)
	// alice all-zeros < bob all-ones; sorted order = a, b.
	concat := append(append([]byte{}, a...), b...)
	digest := sha256.Sum256(concat)
	want := "nxc_" + base64.RawURLEncoding.EncodeToString(digest[:])
	if examplePathID != want {
		t.Errorf("path_id drift: got %s want %s", examplePathID, want)
	}
}

func TestExampleOuterCiphertextSHA256(t *testing.T) {
	const ciphertextB64 = "AAECAwQFBgcICQoLDQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	digest := sha256.Sum256(raw)
	want := hex.EncodeToString(digest[:])
	if exampleCiphertextSHA256Hex != want {
		t.Errorf("ciphertext_sha256 drift: got %s want %s", exampleCiphertextSHA256Hex, want)
	}
}

func TestExampleOuterCanonicalKeyOrder(t *testing.T) {
	// RFC 8785: keys lex-sorted by code-point. For our outer envelope
	// the sorted order is: ciphertext, ciphertext_sha256, msg_id,
	// path_id, ts, version.
	wantPrefix := `{"ciphertext":"`
	if !strings.HasPrefix(exampleOuterCanonical, wantPrefix) {
		t.Errorf("canonical JSON does not start with first lex-sorted key:\n  got:  %.40s\n  want: %s...", exampleOuterCanonical, wantPrefix)
	}
	// Quick check: keys appear in lex order. Find each, confirm offsets ascend.
	keys := []string{`"ciphertext":`, `"ciphertext_sha256":`, `"msg_id":`, `"path_id":`, `"ts":`, `"version":`}
	prev := -1
	for _, k := range keys {
		idx := strings.Index(exampleOuterCanonical, k)
		if idx <= prev {
			t.Errorf("key %s out of order (offset %d, prev %d):\n%s", k, idx, prev, exampleOuterCanonical)
		}
		prev = idx
	}
	// No insignificant whitespace.
	if strings.ContainsAny(exampleOuterCanonical, "\n\t") {
		t.Errorf("canonical JSON contains whitespace — must be no insignificant whitespace per RFC 8785")
	}
	if strings.Contains(exampleOuterCanonical, ": ") {
		t.Errorf("canonical JSON has space after colon")
	}
}

func TestExampleOuterSigVerifies(t *testing.T) {
	seed, _ := hex.DecodeString(aliceSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sig, err := base64.RawURLEncoding.DecodeString(exampleOuterSig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, []byte(exampleOuterCanonical), sig) {
		t.Errorf("outer-envelope signature does not verify — example is broken")
	}
}

func TestExamplesAppearInDiscoveryDoc(t *testing.T) {
	// Sanity: the Examples block populates and is exposed via the top-level Document.
	doc := New("test-nexus")
	if doc.Examples.TestKeys.AlicePubkeyB64u == "" {
		t.Errorf("Examples.TestKeys.AlicePubkeyB64u is empty — buildExamples not wired in")
	}
	if doc.Examples.PairHalf.V2.Signature == "" {
		t.Errorf("Examples.PairHalf.V2.Signature is empty")
	}
	if doc.Examples.PairHalf.V1.Signature == "" {
		t.Errorf("Examples.PairHalf.V1.Signature is empty")
	}
	if _, ok := doc.Examples.PairHalf.V2.WireJSON["dh_pubkey"]; !ok {
		t.Errorf("Examples.PairHalf.V2.WireJSON missing dh_pubkey")
	}
	if doc.Examples.OuterEnvelope.XNexusSignature == "" {
		t.Errorf("Examples.OuterEnvelope.XNexusSignature is empty")
	}
	if doc.Examples.PathIDDerivation.Result == "" {
		t.Errorf("Examples.PathIDDerivation.Result is empty")
	}
}
