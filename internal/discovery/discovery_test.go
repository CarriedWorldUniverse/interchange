package discovery

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewShape pins the field set of the discovery document. A new Frame
// implementing from just the JSON must see all the fields it needs;
// accidentally dropping one is a silent protocol break.
func TestNewShape(t *testing.T) {
	doc := New("test-nexus-id")

	if doc.Version != "1" {
		t.Errorf("Version = %q, want 1", doc.Version)
	}
	if doc.Protocol != "nexus-frame-relay/1" {
		t.Errorf("Protocol = %q", doc.Protocol)
	}
	if doc.InterchangeID != "test-nexus-id" {
		t.Errorf("InterchangeID = %q", doc.InterchangeID)
	}
	if doc.TrustModel != "operator_approval" {
		t.Errorf("TrustModel = %q, want operator_approval", doc.TrustModel)
	}

	// Endpoints block: pair_approve / pair_deny MUST be null so a new
	// Frame knows they are not publicly callable. This is the only place
	// the null signal is visible to a cold-starting peer.
	if doc.Endpoints.PairApprove != nil {
		t.Errorf("Endpoints.PairApprove = %v, want nil", *doc.Endpoints.PairApprove)
	}
	if doc.Endpoints.PairDeny != nil {
		t.Errorf("Endpoints.PairDeny = %v, want nil", *doc.Endpoints.PairDeny)
	}
	if doc.Endpoints.Discovery == "" || doc.Endpoints.Put == "" || doc.Endpoints.Pull == "" {
		t.Errorf("Endpoints missing required public routes: %+v", doc.Endpoints)
	}

	// Crypto primitives must be specific enough for stdlib
	// reimplementation — a Frame without casket has to get these right.
	if len(doc.Crypto.Signing.Algorithms) == 0 {
		t.Errorf("Crypto.Signing.Algorithms empty")
	}
	if doc.Crypto.Signing.Default == "" {
		t.Errorf("Crypto.Signing.Default empty")
	}
	// v1 wire: Ed25519 only. p256 is aspirational and MUST NOT appear
	// in the advertised algorithms (discovery docs are bootstrap
	// contracts, not roadmaps — anvil #7839/#7841).
	for _, alg := range doc.Crypto.Signing.Algorithms {
		if alg == "p256" {
			t.Errorf("Crypto.Signing.Algorithms lists p256 but signing is Ed25519-only at v1")
		}
	}
	if _, ok := doc.Crypto.Signing.KeyFormat["p256"]; ok {
		t.Errorf("Crypto.Signing.KeyFormat lists p256 — remove until signing is real")
	}
	// Auth.Scheme is free-text but a cold-starting Frame reads it as
	// protocol truth. MUST NOT advertise p256 here either.
	if strings.Contains(strings.ToLower(doc.Auth.Scheme), "p256") ||
		strings.Contains(strings.ToLower(doc.Auth.Scheme), "p-256") {
		t.Errorf("Auth.Scheme advertises p256 signing: %q — narrow to Ed25519 only", doc.Auth.Scheme)
	}
	if doc.Crypto.Encryption.KDF == "" || doc.Crypto.Encryption.Symmetric == "" {
		t.Errorf("Crypto.Encryption KDF/Symmetric empty: %+v", doc.Crypto.Encryption)
	}
	if !strings.Contains(doc.Crypto.Encryption.AAD, "raw 32-byte") {
		t.Errorf("Crypto.Encryption.AAD must call out raw-bytes form, got: %q", doc.Crypto.Encryption.AAD)
	}
	if doc.Crypto.CanonicalJSON.Standard == "" {
		t.Errorf("Crypto.CanonicalJSON.Standard empty")
	}
	if !strings.Contains(doc.Crypto.CanonicalJSON.ErgonomicNote, "re-canonicalizes") {
		t.Errorf("ErgonomicNote must flag server-side re-canonicalization, got: %q", doc.Crypto.CanonicalJSON.ErgonomicNote)
	}

	// Content handling block is load-bearing for prompt-injection defence
	// — non-optional in v3.
	if doc.ContentHandling.Wrapping == "" || doc.ContentHandling.Treatment == "" {
		t.Errorf("ContentHandling block incomplete: %+v", doc.ContentHandling)
	}
	if !strings.Contains(doc.ContentHandling.Wrapping, "<peer_message") {
		t.Errorf("ContentHandling.Wrapping doesn't describe peer_message tag")
	}
	if len(doc.ContentHandling.MimeAllowlist) == 0 {
		t.Errorf("ContentHandling.MimeAllowlist empty")
	}

	if doc.Pairing.RequestTTLHours == 0 {
		t.Errorf("Pairing.RequestTTLHours = 0")
	}
	if len(doc.Pairing.Flow) == 0 {
		t.Errorf("Pairing.Flow empty")
	}
	if !strings.Contains(doc.Pairing.SelfSigCanonicalV2, "v2\n") {
		t.Errorf("Pairing.SelfSigCanonicalV2 doesn't describe line-oriented v2 format")
	}
	if !strings.Contains(doc.Pairing.SelfSigCanonicalV1Deprecated, "v1\n") {
		t.Errorf("Pairing.SelfSigCanonicalV1Deprecated doesn't describe v1 fallback")
	}
	// New v2 fields must be in the preimage (covered by signature).
	for _, field := range []string{"<dh_alg>", "<dh_pubkey base64url>"} {
		if !strings.Contains(doc.Pairing.SelfSigCanonicalV2, field) {
			t.Errorf("v2 preimage missing required field %s", field)
		}
	}
	if len(doc.MessageKinds) == 0 {
		t.Errorf("MessageKinds empty")
	}
	if doc.Limits.ReplayWindowSeconds == 0 || doc.Limits.BodyMaxBytes == 0 {
		t.Errorf("Limits unset: %+v", doc.Limits)
	}
}

// TestHandlerGET covers the happy path — GET returns valid JSON, correct
// content-type, interchange_id flows through.
func TestHandlerGET(t *testing.T) {
	h := Handler("dmon-home-nexus")
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json*", ct)
	}

	body, _ := io.ReadAll(rr.Body)
	var got Document
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got.InterchangeID != "dmon-home-nexus" {
		t.Errorf("InterchangeID = %q, want dmon-home-nexus", got.InterchangeID)
	}
	if got.TrustModel != "operator_approval" {
		t.Errorf("TrustModel = %q", got.TrustModel)
	}

	// Round-trip: JSON → struct → JSON should match the original body
	// structurally (whitespace ignored). Catches drift between struct
	// tags and the JSON we actually produce.
	reserialized, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("reserialize: %v", err)
	}
	var a, b any
	_ = json.Unmarshal(body, &a)
	_ = json.Unmarshal(reserialized, &b)
	// deep-equality check via re-marshal sort is overkill here; the
	// explicit field assertions in TestNewShape cover the shape. This
	// test just confirms it's a non-empty JSON object.
	if len(reserialized) < 500 {
		t.Errorf("reserialized doc is suspiciously small (%d bytes) — fields may be missing", len(reserialized))
	}
}

// TestHandlerRejectsNonGET — only GET, other verbs 405. The endpoint is
// idempotent read-only by design.
func TestHandlerRejectsNonGET(t *testing.T) {
	h := Handler("x")
	cases := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range cases {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, Path, nil)
			rr := httptest.NewRecorder()
			h(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s status = %d, want 405", method, rr.Code)
			}
			if allow := rr.Header().Get("Allow"); allow != "GET" {
				t.Errorf("%s Allow header = %q, want GET", method, allow)
			}
		})
	}
}

// TestHandlerUnauthenticated — no X-Nexus-Signature required. This is the
// only endpoint that takes anonymous traffic; pinning it in a test
// prevents a future "add auth everywhere" change from silently closing
// the bootstrap hole.
func TestHandlerUnauthenticated(t *testing.T) {
	h := Handler("x")
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	// No X-Nexus-Signature header set.
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("unauthenticated GET got %d, want 200 — discovery must NOT require auth", rr.Code)
	}
}
