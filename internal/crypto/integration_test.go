package crypto_test

// Integration test: real Ed25519 signing + real mailbox Handler +
// EdVerifier. End-to-end proof that a properly-signed PUT lands stored
// and a bad signature 401s.
//
// Kept in _test package (not crypto) because it imports mailbox, which
// in turn imports storage — and a test inside the crypto package would
// create an import cycle. This file sits alongside crypto_test.go but
// uses the external-test-package convention.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CarriedWorldUniverse/interchange/internal/crypto"
	"github.com/CarriedWorldUniverse/interchange/internal/mailbox"
	"github.com/CarriedWorldUniverse/interchange/internal/storage"
)

// setupWithRealPair stands up a storage + pair with real Ed25519 keys
// and returns everything needed to sign+send an envelope.
func setupWithRealPair(t *testing.T) (*mailbox.Handler, storage.Pair, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	s, err := storage.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateSchema(context.Background()); err != nil {
		t.Fatal(err)
	}

	reqPub, reqPriv, _ := ed25519.GenerateKey(nil)
	ownPub, ownPriv, _ := ed25519.GenerateKey(nil)
	pair := storage.Pair{
		PathID:            "nxc_" + strings.Repeat("a", 43),
		RequesterID:       "requester",
		RequesterPubkey:   base64.RawURLEncoding.EncodeToString(reqPub),
		RequesterDHPubkey: "req-dh",
		OwnerID:           "owner",
		OwnerPubkey:       base64.RawURLEncoding.EncodeToString(ownPub),
		OwnerDHPubkey:     "own-dh",
		SigAlg:            "ed25519",
		DhAlg:             "P-256",
		ActivatedAt:       time.Now().UTC(),
	}
	if err := s.InsertPair(context.Background(), pair); err != nil {
		t.Fatal(err)
	}

	h := &mailbox.Handler{
		Store:    s,
		Verifier: crypto.EdVerifier{},
		Clock:    func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) },
	}
	return h, pair, reqPriv, ownPriv
}

// canonicalJSONMatchingHandler mirrors what the mailbox handler does
// server-side when verifying signatures: marshal the six envelope
// fields in sorted order with SetEscapeHTML(false). Client-side signing
// MUST produce bytes the handler produces on re-canonicalization.
//
// We avoid importing the handler's private canonicalJSON func; instead
// we construct bytes in the same shape so the signature verifies. This
// is what a real casket-go-powered Nexus client would do (once Phase 3
// is built).
func canonicalEnvelope(msgID, ts, pathID, ctSha, ct string) []byte {
	// Field order: alphabetical by JSON key (mailbox handler enforces
	// this via struct order).
	type canonicalEnv struct {
		Ciphertext       string `json:"ciphertext"`
		CiphertextSHA256 string `json:"ciphertext_sha256"`
		MsgID            string `json:"msg_id"`
		PathID           string `json:"path_id"`
		Ts               string `json:"ts"`
		Version          string `json:"version"`
	}
	e := canonicalEnv{
		Ciphertext:       ct,
		CiphertextSHA256: ctSha,
		MsgID:            msgID,
		PathID:           pathID,
		Ts:               ts,
		Version:          "1",
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(e)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

const msgID = "0194a81e-73c4-7001-8aaa-000000000001"

func TestEndToEndPutSignedByRequester(t *testing.T) {
	h, pair, reqPriv, _ := setupWithRealPair(t)

	ciphertext := []byte("opaque-ciphertext")
	ctB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	digest := sha256.Sum256(ciphertext)
	ctSha := hex.EncodeToString(digest[:])
	ts := "2026-04-25T12:00:00Z"

	canonical := canonicalEnvelope(msgID, ts, pair.PathID, ctSha, ctB64)
	sig := ed25519.Sign(reqPriv, canonical)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// Body = non-canonical (normal) JSON for transport. Handler
	// re-canonicalizes server-side before verifying. This exercises
	// the "ergonomic note" path that the discovery doc advertises.
	bodyBytes, _ := json.Marshal(map[string]string{
		"version":           "1",
		"msg_id":            msgID,
		"ts":                ts,
		"path_id":           pair.PathID,
		"ciphertext_sha256": ctSha,
		"ciphertext":        ctB64,
	})

	req := httptest.NewRequest(http.MethodPut, "/mailbox/"+pair.PathID, bytes.NewReader(bodyBytes))
	req.Header.Set("X-Nexus-Signature", sigB64)
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestEndToEndBadSignatureStill401s(t *testing.T) {
	h, pair, _, _ := setupWithRealPair(t)

	// Generate a signature with a key that isn't in the pair.
	_, thirdPriv, _ := ed25519.GenerateKey(nil)

	ciphertext := []byte("opaque")
	ctB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	digest := sha256.Sum256(ciphertext)
	ctSha := hex.EncodeToString(digest[:])
	ts := "2026-04-25T12:00:00Z"

	canonical := canonicalEnvelope(msgID, ts, pair.PathID, ctSha, ctB64)
	sig := ed25519.Sign(thirdPriv, canonical) // imposter!
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	bodyBytes, _ := json.Marshal(map[string]string{
		"version": "1", "msg_id": msgID, "ts": ts, "path_id": pair.PathID,
		"ciphertext_sha256": ctSha, "ciphertext": ctB64,
	})
	req := httptest.NewRequest(http.MethodPut, "/mailbox/"+pair.PathID, bytes.NewReader(bodyBytes))
	req.Header.Set("X-Nexus-Signature", sigB64)
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (impostor sig rejected)", rr.Code)
	}
}

// TestEndToEndRecanonicalizationForgiveness pins the ergonomic note in
// the discovery doc: a client that produces structurally-equivalent
// JSON (correct fields + values) but different whitespace/key-order
// still verifies, because the handler re-canonicalizes server-side.
func TestEndToEndRecanonicalizationForgiveness(t *testing.T) {
	h, pair, reqPriv, _ := setupWithRealPair(t)

	ciphertext := []byte("opaque")
	ctB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	digest := sha256.Sum256(ciphertext)
	ctSha := hex.EncodeToString(digest[:])
	ts := "2026-04-25T12:00:00Z"

	// Client signs over canonical bytes (same as handler produces).
	canonical := canonicalEnvelope(msgID, ts, pair.PathID, ctSha, ctB64)
	sig := ed25519.Sign(reqPriv, canonical)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// Transport body: out-of-order fields + indented whitespace. This
	// would NOT byte-match canonical, but structural content is the
	// same — handler re-canonicalizes and verification succeeds.
	body := []byte(`{
  "version": "1",
  "ts": "` + ts + `",
  "msg_id": "` + msgID + `",
  "path_id": "` + pair.PathID + `",
  "ciphertext": "` + ctB64 + `",
  "ciphertext_sha256": "` + ctSha + `"
}`)

	req := httptest.NewRequest(http.MethodPut, "/mailbox/"+pair.PathID, bytes.NewReader(body))
	req.Header.Set("X-Nexus-Signature", sigB64)
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("status = %d body = %s — re-canonicalization ergonomic broke",
			rr.Code, rr.Body.String())
	}
}
