package mailbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CarriedWorldUniverse/interchange/internal/storage"
)

// fakeVerifier identifies the caller based on a prefix of the
// signature header — test-only shortcut that replaces real crypto with
// a deterministic mapping. Used until Part 2.5 wires stdlib Ed25519/P-256.
type fakeVerifier struct {
	requesterPubkey string
	ownerPubkey     string
}

func (f *fakeVerifier) Identify(_ context.Context, pair storage.Pair, sig string, _ []byte) (string, error) {
	switch {
	case strings.HasPrefix(sig, "requester:"):
		return pair.RequesterPubkey, nil
	case strings.HasPrefix(sig, "owner:"):
		return pair.OwnerPubkey, nil
	case sig == "":
		return "", nil
	case strings.HasPrefix(sig, "bogus:"):
		return "", nil
	case strings.HasPrefix(sig, "impostor:"):
		// Return a pubkey that isn't in the pair — pins the
		// "sender_not_in_pair" safety net.
		return "impostor-pubkey-not-in-any-pair", nil
	default:
		return "", nil
	}
}

func newFixture(t *testing.T) (*Handler, storage.Pair) {
	t.Helper()
	s, err := storage.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	pair := storage.Pair{
		PathID:            "nxc_" + strings.Repeat("a", 43),
		RequesterID:       "bob",
		RequesterPubkey:   "req-pubkey",
		RequesterDHPubkey: "req-dh",
		OwnerID:           "alice",
		OwnerPubkey:       "own-pubkey",
		OwnerDHPubkey:     "own-dh",
		SigAlg:            "ed25519",
		DhAlg:             "P-256",
		ActivatedAt:       time.Now().UTC(),
	}
	if err := s.InsertPair(context.Background(), pair); err != nil {
		t.Fatalf("insert pair: %v", err)
	}
	h := &Handler{
		Store:    s,
		Verifier: &fakeVerifier{},
		Clock:    func() time.Time { return time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC) },
	}
	return h, pair
}

// sampleEnvelope builds an OuterEnvelope with matching ciphertext hash
// and the fixture clock's timestamp.
func sampleEnvelope(pathID, msgID string, ts time.Time) (OuterEnvelope, []byte) {
	ciphertext := []byte("sample-ciphertext-content")
	ctB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	digest := sha256.Sum256(ciphertext)
	env := OuterEnvelope{
		Version:          "1",
		MsgID:            msgID,
		Ts:               ts.Format("2006-01-02T15:04:05Z"),
		PathID:           pathID,
		CiphertextSHA256: hex.EncodeToString(digest[:]),
		Ciphertext:       ctB64,
	}
	body, _ := json.Marshal(env)
	return env, body
}

const validMsgID1 = "0194a81e-73c4-7001-8aaa-000000000001"
const validMsgID2 = "0194a81e-73c4-7002-8aaa-000000000002"
const validMsgID3 = "0194a81e-73c4-7003-8aaa-000000000003"

func doRequest(t *testing.T, h *Handler, method, url string, body []byte, sigHeader string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, url, r)
	if sigHeader != "" {
		req.Header.Set("X-Nexus-Signature", sigHeader)
	}
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	return rr
}

func TestPutHappyPath(t *testing.T) {
	h, pair := newFixture(t)
	_, body := sampleEnvelope(pair.PathID, validMsgID1, h.now())

	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["msg_id"] != validMsgID1 {
		t.Errorf("response msg_id = %q", resp["msg_id"])
	}
}

func TestPutDuplicateReturns409(t *testing.T) {
	h, pair := newFixture(t)
	_, body := sampleEnvelope(pair.PathID, validMsgID1, h.now())

	_ = doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")
	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rr.Code)
	}
}

func TestPutUnknownPair404(t *testing.T) {
	h, _ := newFixture(t)
	_, body := sampleEnvelope("nxc_"+strings.Repeat("z", 43), validMsgID1, h.now())
	rr := doRequest(t, h, http.MethodPut, "/mailbox/nxc_"+strings.Repeat("z", 43), body, "requester:sig")
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestPutUnsigned401(t *testing.T) {
	h, pair := newFixture(t)
	_, body := sampleEnvelope(pair.PathID, validMsgID1, h.now())
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestPutBadSig401(t *testing.T) {
	h, pair := newFixture(t)
	_, body := sampleEnvelope(pair.PathID, validMsgID1, h.now())
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "bogus:whatever")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// TestPutImpostor401 regression-pins the "sender_not_in_pair" guard: a
// Verifier returning a pubkey that doesn't match either pair half must
// still fail the request. Verifiers shouldn't do this, but if they did
// (buggy impl, test stub bug), the handler must fail closed rather than
// accept a non-party message.
func TestPutImpostor401(t *testing.T) {
	h, pair := newFixture(t)
	_, body := sampleEnvelope(pair.PathID, validMsgID1, h.now())
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "impostor:x")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestPutRejectsPathIDMismatch(t *testing.T) {
	h, pair := newFixture(t)
	// Envelope carries the valid pathID, but we PUT it to a different URL.
	_, body := sampleEnvelope(pair.PathID, validMsgID1, h.now())
	otherPath := "nxc_" + strings.Repeat("b", 43)
	// Register that other path so we get past the 404 and into the
	// schema check.
	_ = h.Store.InsertPair(context.Background(), storage.Pair{
		PathID: otherPath, RequesterID: "x", RequesterPubkey: "rx", RequesterDHPubkey: "rdx",
		OwnerID: "y", OwnerPubkey: "oy", OwnerDHPubkey: "ody",
		SigAlg: "ed25519", DhAlg: "P-256", ActivatedAt: h.now(),
	})
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+otherPath, body, "requester:sig")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "path_id_mismatch") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

func TestPutRejectsStaleTimestamp(t *testing.T) {
	h, pair := newFixture(t)
	stale := h.now().Add(-10 * time.Minute)
	_, body := sampleEnvelope(pair.PathID, validMsgID1, stale)
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (replay window)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ts_out_of_window") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

func TestPutRejectsBadCiphertextHash(t *testing.T) {
	h, pair := newFixture(t)
	env, _ := sampleEnvelope(pair.PathID, validMsgID1, h.now())
	env.CiphertextSHA256 = strings.Repeat("0", 64)
	body, _ := json.Marshal(env)
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "hash_mismatch") {
		t.Errorf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestPutRejectsInvalidMsgID(t *testing.T) {
	h, pair := newFixture(t)
	env, _ := sampleEnvelope(pair.PathID, "not-a-uuid", h.now())
	body, _ := json.Marshal(env)
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestPutRejectsInvalidJSON(t *testing.T) {
	h, pair := newFixture(t)
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, []byte("not json"), "requester:sig")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestPutInvalidPathID(t *testing.T) {
	h, _ := newFixture(t)
	rr := doRequest(t, h, http.MethodPut, "/mailbox/not-a-valid-path", []byte("{}"), "requester:sig")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestGetReturnsEnvelopesForReader(t *testing.T) {
	h, pair := newFixture(t)

	// Requester PUTs two envelopes.
	for _, id := range []string{validMsgID1, validMsgID2} {
		_, body := sampleEnvelope(pair.PathID, id, h.now())
		if rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig"); rr.Code != http.StatusAccepted {
			t.Fatalf("seed %s: %d %s", id, rr.Code, rr.Body.String())
		}
	}

	// Owner reads — direction B_to_A wait, no: requester sent A_to_B, so
	// owner reads A_to_B (envelopes addressed to owner).
	rr := doRequest(t, h, http.MethodGet, "/mailbox/"+pair.PathID, nil, "owner:sig")
	if rr.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Envelopes []json.RawMessage `json:"envelopes"`
		Cursor    *string           `json:"cursor"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Envelopes) != 2 {
		t.Errorf("envelopes = %d, want 2", len(resp.Envelopes))
	}
	if resp.Cursor == nil || *resp.Cursor != validMsgID2 {
		t.Errorf("cursor = %v, want %s", resp.Cursor, validMsgID2)
	}
}

// TestGetIsolatesDirection is the critical invariant: a side cannot read
// its own sent messages by calling GET. Requester PUTs, then requester
// GETs — should see empty, not their own outbox.
func TestGetIsolatesDirection(t *testing.T) {
	h, pair := newFixture(t)
	_, body := sampleEnvelope(pair.PathID, validMsgID1, h.now())
	_ = doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")

	rr := doRequest(t, h, http.MethodGet, "/mailbox/"+pair.PathID, nil, "requester:sig")
	if rr.Code != http.StatusOK {
		t.Fatalf("get: %d", rr.Code)
	}
	var resp struct {
		Envelopes []json.RawMessage `json:"envelopes"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Envelopes) != 0 {
		t.Errorf("requester sees own outbox: %d envelopes", len(resp.Envelopes))
	}
}

func TestGetSinceCursor(t *testing.T) {
	h, pair := newFixture(t)
	for _, id := range []string{validMsgID1, validMsgID2, validMsgID3} {
		_, body := sampleEnvelope(pair.PathID, id, h.now())
		_ = doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")
	}

	rr := doRequest(t, h, http.MethodGet, "/mailbox/"+pair.PathID+"?since="+validMsgID1, nil, "owner:sig")
	if rr.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Envelopes []json.RawMessage `json:"envelopes"`
		Cursor    *string           `json:"cursor"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Envelopes) != 2 {
		t.Errorf("envelopes = %d, want 2", len(resp.Envelopes))
	}
}

func TestGetUnsigned401(t *testing.T) {
	h, pair := newFixture(t)
	rr := doRequest(t, h, http.MethodGet, "/mailbox/"+pair.PathID, nil, "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestGetInvalidSince(t *testing.T) {
	h, pair := newFixture(t)
	rr := doRequest(t, h, http.MethodGet, "/mailbox/"+pair.PathID+"?since=not-a-uuid", nil, "owner:sig")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestAckEvictsCallerEnvelopes(t *testing.T) {
	h, pair := newFixture(t)
	for _, id := range []string{validMsgID1, validMsgID2} {
		_, body := sampleEnvelope(pair.PathID, id, h.now())
		_ = doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")
	}

	// Owner acks msg 1 — requester's envelope addressed to owner.
	ackBody, _ := json.Marshal(map[string][]string{"ids": {validMsgID1}})
	rr := doRequest(t, h, http.MethodPost, "/mailbox/"+pair.PathID+"/ack", ackBody, "owner:sig")
	if rr.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]int
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["evicted"] != 1 {
		t.Errorf("evicted = %d, want 1", resp["evicted"])
	}

	// Second GET by owner should see only msg 2.
	rr = doRequest(t, h, http.MethodGet, "/mailbox/"+pair.PathID, nil, "owner:sig")
	var got struct {
		Envelopes []json.RawMessage `json:"envelopes"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if len(got.Envelopes) != 1 {
		t.Errorf("after ack: envelopes = %d, want 1", len(got.Envelopes))
	}
}

// TestAckIsolationOneSideCannotEvictOther pins the rule that one
// identity cannot evict envelopes it did not receive. Requester tries
// to ack a message that was addressed to them — but requester sent it,
// so it's in the owner's inbox, not requester's. Ack should be no-op.
func TestAckIsolationOneSideCannotEvictOther(t *testing.T) {
	h, pair := newFixture(t)
	_, body := sampleEnvelope(pair.PathID, validMsgID1, h.now())
	_ = doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "requester:sig")

	// Requester tries to ack own sent message — should evict 0.
	ackBody, _ := json.Marshal(map[string][]string{"ids": {validMsgID1}})
	rr := doRequest(t, h, http.MethodPost, "/mailbox/"+pair.PathID+"/ack", ackBody, "requester:sig")
	if rr.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]int
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["evicted"] != 0 {
		t.Errorf("requester evicted own sent: %d (must be 0)", resp["evicted"])
	}

	// Envelope still there for owner.
	rr = doRequest(t, h, http.MethodGet, "/mailbox/"+pair.PathID, nil, "owner:sig")
	var got struct {
		Envelopes []json.RawMessage `json:"envelopes"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if len(got.Envelopes) != 1 {
		t.Errorf("envelope missing after failed cross-side ack: %d", len(got.Envelopes))
	}
}

func TestAckEmptyIDs(t *testing.T) {
	h, pair := newFixture(t)
	ackBody, _ := json.Marshal(map[string][]string{"ids": {}})
	rr := doRequest(t, h, http.MethodPost, "/mailbox/"+pair.PathID+"/ack", ackBody, "owner:sig")
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestAckTooManyIDs(t *testing.T) {
	h, pair := newFixture(t)
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = validMsgID1
	}
	ackBody, _ := json.Marshal(map[string][]string{"ids": ids})
	rr := doRequest(t, h, http.MethodPost, "/mailbox/"+pair.PathID+"/ack", ackBody, "owner:sig")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h, pair := newFixture(t)
	rr := doRequest(t, h, http.MethodDelete, "/mailbox/"+pair.PathID, nil, "")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d", rr.Code)
	}
	if rr.Header().Get("Allow") == "" {
		t.Errorf("Allow header missing on 405")
	}
}

// TestCanonicalJSONNoHTMLEscape pins cross-runtime parity: Go's default
// encoding/json escapes `<`, `>`, `&` as < / > / &, while
// the TS reference's JSON.stringify and RFC 8785 JCS do not. If Go's
// default ever leaks back into canonicalJSON, a TS client signing a
// field containing any of those chars would get 401 signature_invalid
// despite a correct signature. This test catches that regression.
//
// The current OuterEnvelope fields are all ASCII-safe (base64url, hex,
// UUID, ISO8601, constant "1"), so the bug is latent not active, but
// the invariant is cheap to pin.
func TestCanonicalJSONNoHTMLEscape(t *testing.T) {
	e := OuterEnvelope{
		Version:          "1",
		MsgID:            validMsgID1,
		Ts:               "2026-04-24T12:00:00Z",
		PathID:           "nxc_x",
		CiphertextSHA256: "abc",
		// Force the test: inject the chars Go would otherwise escape.
		// This is not a legitimate base64url value — the test is
		// about canonicalJSON's output shape, not envelope validation.
		Ciphertext: "<>&",
	}
	out, err := canonicalJSON(e)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	s := string(out)
	// Go's default encoding/json escapes '<' as "<", '>' as
	// ">", '&' as "&". With SetEscapeHTML(false) these appear
	// literally. Detecting the Unicode-escape sequences would indicate
	// SetEscapeHTML stopped working — use rune-level codepoints so the
	// test can't be misread.
	badEscapes := []string{"\\u003c", "\\u003e", "\\u0026"}
	for _, esc := range badEscapes {
		if strings.Contains(s, esc) {
			t.Errorf("canonicalJSON emitted %s — SetEscapeHTML is leaking: %s", esc, s)
		}
	}
	// And the literal <>& MUST round-trip verbatim.
	if !strings.Contains(s, `"<>&"`) {
		t.Errorf("expected literal <>& in output, got: %s", s)
	}
	// No trailing newline (JCS forbids it).
	if strings.HasSuffix(s, "\n") {
		t.Errorf("trailing newline in canonical output: %q", s)
	}
}

// TestStubVerifierFailsClosed — if someone forgets to install a real
// Verifier in production, the StubVerifier default must reject every
// request rather than silently accept unsigned traffic.
func TestStubVerifierFailsClosed(t *testing.T) {
	s, _ := storage.OpenSQLite(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	_ = s.CreateSchema(context.Background())
	pair := storage.Pair{
		PathID: "nxc_" + strings.Repeat("a", 43), RequesterID: "b", RequesterPubkey: "rp", RequesterDHPubkey: "rd",
		OwnerID: "o", OwnerPubkey: "op", OwnerDHPubkey: "od",
		SigAlg: "ed25519", DhAlg: "P-256", ActivatedAt: time.Now().UTC(),
	}
	_ = s.InsertPair(context.Background(), pair)

	h := &Handler{Store: s, Verifier: StubVerifier{}}
	_, body := sampleEnvelope(pair.PathID, validMsgID1, time.Now().UTC())
	rr := doRequest(t, h, http.MethodPut, "/mailbox/"+pair.PathID, body, "any-sig")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("StubVerifier accepted traffic: status=%d (MUST reject)", rr.Code)
	}
	// Assert the 401 came via signature_invalid, not sender_not_in_pair.
	// If StubVerifier were "helpfully" changed to return a default
	// pubkey, it would still 401 — but via the sender_not_in_pair path.
	// This catches that drift: StubVerifier MUST return empty pubkey.
	if !strings.Contains(rr.Body.String(), "signature_invalid") {
		t.Errorf("StubVerifier 401 body = %q, want signature_invalid — did someone make StubVerifier return a default pubkey?", rr.Body.String())
	}
}
