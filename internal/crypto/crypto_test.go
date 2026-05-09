package crypto

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/CarriedWorldUniverse/interchange/internal/storage"
)

// makePair generates a real Ed25519 key for each side and returns a
// storage.Pair populated with their base64url-encoded wire-format
// pubkeys, plus the private keys for signing test messages.
func makePair(t *testing.T) (storage.Pair, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	reqPub, reqPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ownPub, ownPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pair := storage.Pair{
		PathID:          "nxc_test",
		RequesterID:     "bob",
		RequesterPubkey: base64.RawURLEncoding.EncodeToString(reqPub),
		OwnerID:         "alice",
		OwnerPubkey:     base64.RawURLEncoding.EncodeToString(ownPub),
		SigAlg:          "ed25519",
		DhAlg:           "P-256",
		ActivatedAt:     time.Now().UTC(),
	}
	return pair, reqPriv, ownPriv
}

func TestIdentifiesRequesterByValidSignature(t *testing.T) {
	pair, reqPriv, _ := makePair(t)
	msg := []byte("canonical message")
	sig := ed25519.Sign(reqPriv, msg)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	got, err := EdVerifier{}.Identify(context.Background(), pair, sigB64, msg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != pair.RequesterPubkey {
		t.Errorf("got = %q, want requester pubkey %q", got, pair.RequesterPubkey)
	}
}

func TestIdentifiesOwnerByValidSignature(t *testing.T) {
	pair, _, ownPriv := makePair(t)
	msg := []byte("canonical message")
	sig := ed25519.Sign(ownPriv, msg)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	got, err := EdVerifier{}.Identify(context.Background(), pair, sigB64, msg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != pair.OwnerPubkey {
		t.Errorf("got = %q, want owner pubkey %q", got, pair.OwnerPubkey)
	}
}

func TestRejectsInvalidSignature(t *testing.T) {
	pair, reqPriv, _ := makePair(t)
	sig := ed25519.Sign(reqPriv, []byte("original message"))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// Verify against different bytes — the signature is valid but
	// not over THIS message, so verification must fail.
	got, err := EdVerifier{}.Identify(context.Background(), pair, sigB64, []byte("tampered message"))
	if err != nil {
		t.Errorf("err = %v, want nil (bad sig is 401 not 500)", err)
	}
	if got != "" {
		t.Errorf("got = %q, want empty (unauthenticated)", got)
	}
}

func TestRejectsUnregisteredSigner(t *testing.T) {
	pair, _, _ := makePair(t)
	// Third-party key — signs correctly but isn't in the pair.
	_, thirdPriv, _ := ed25519.GenerateKey(nil)
	msg := []byte("impostor")
	sig := ed25519.Sign(thirdPriv, msg)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	got, err := EdVerifier{}.Identify(context.Background(), pair, sigB64, msg)
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if got != "" {
		t.Errorf("impostor identified as %q — pair isolation broken", got)
	}
}

func TestEmptySignature(t *testing.T) {
	pair, _, _ := makePair(t)
	got, err := EdVerifier{}.Identify(context.Background(), pair, "", []byte("msg"))
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if got != "" {
		t.Errorf("empty sig identified as %q", got)
	}
}

func TestMalformedBase64(t *testing.T) {
	pair, _, _ := makePair(t)
	got, err := EdVerifier{}.Identify(context.Background(), pair, "not!base64!url", []byte("msg"))
	if err != nil {
		t.Errorf("err = %v, want nil (malformed sig is 401 not 500)", err)
	}
	if got != "" {
		t.Errorf("malformed sig identified as %q", got)
	}
}

func TestWrongSignatureSize(t *testing.T) {
	pair, _, _ := makePair(t)
	// Valid base64 but wrong byte length for Ed25519.
	shortSig := base64.RawURLEncoding.EncodeToString([]byte("too-short"))
	got, err := EdVerifier{}.Identify(context.Background(), pair, shortSig, []byte("msg"))
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if got != "" {
		t.Errorf("short sig identified as %q", got)
	}
}

// TestRejectsUnsupportedSigAlg pins that a pair with sig_alg != ed25519
// surfaces an error (not silent 401). Part 2.5b rejects these at
// /pair/request so they shouldn't exist, but the guard is cheap and
// documents the v1 invariant.
func TestRejectsUnsupportedSigAlg(t *testing.T) {
	pair, reqPriv, _ := makePair(t)
	pair.SigAlg = "p256" // simulate a drift / data-integrity hole
	msg := []byte("msg")
	sig := ed25519.Sign(reqPriv, msg)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	got, err := EdVerifier{}.Identify(context.Background(), pair, sigB64, msg)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
	if got != "" {
		t.Errorf("got = %q on unsupported alg", got)
	}
}

// TestMalformedStoredPubkey — if a pair was somehow stored with a
// non-base64 pubkey (data corruption, migration bug), surface an error
// so the operator notices rather than silently 401-ing forever.
// Requires a decodable signature of the correct length so we reach the
// pubkey-decode step.
func TestMalformedStoredPubkey(t *testing.T) {
	pair, _, _ := makePair(t)
	pair.RequesterPubkey = "not!valid!base64"

	// A syntactically valid (64-byte) Ed25519 signature so the handler
	// proceeds past the sig-decode guard and into pubkey iteration.
	dummySig := make([]byte, ed25519.SignatureSize)
	sigB64 := base64.RawURLEncoding.EncodeToString(dummySig)

	_, err := EdVerifier{}.Identify(context.Background(), pair, sigB64, []byte("msg"))
	if err == nil {
		t.Errorf("err = nil, want error on malformed stored pubkey")
	}
}

// TestPaddedAndUnpaddedBase64Accepted — decoder accepts both forms for
// interop tolerance. Spec uses unpadded (casket-go default), but some
// non-casket clients may pad.
func TestPaddedAndUnpaddedBase64Accepted(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("padding-test")
	sig := ed25519.Sign(priv, msg)

	unpadded := base64.RawURLEncoding.EncodeToString(sig)
	padded := base64.URLEncoding.EncodeToString(sig)
	if unpadded == padded {
		// Ed25519 sigs are 64 bytes — always divisible by 3? No, 64/3=21.33
		// so there IS padding. This guard just confirms the test exercises
		// both forms meaningfully.
		t.Skip("signature length happened to be multiple of 3")
	}

	// Both forms should decode successfully via decodeB64URL.
	for _, form := range []string{unpadded, padded} {
		out, err := decodeB64URL(form)
		if err != nil {
			t.Errorf("decode %q: %v", form, err)
		}
		if len(out) != ed25519.SignatureSize {
			t.Errorf("decoded len = %d, want %d", len(out), ed25519.SignatureSize)
		}
	}
}
