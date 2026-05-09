// Package mailbox serves the PUT/GET/ack endpoints that carry envelopes
// between paired Frames. It is content-blind: envelopes are stored as
// opaque ciphertext + outer JSON, never decrypted.
//
// Signature verification is factored behind Verifier so Part 2.3 can land
// the HTTP shape while Part 2.5 plugs in real crypto. The default
// StubVerifier fails closed — any configured production deployment that
// forgets to install a real Verifier will 401 every request rather than
// silently letting unsigned traffic through.
package mailbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/CarriedWorldUniverse/interchange/internal/storage"
)

const (
	replayWindow = 5 * time.Minute
	maxAckBatch  = 100
)

// pathIDRegex validates "nxc_" + base64url-unpadded-SHA-256 (exactly 43
// chars: 32 bytes → ⌈32×4/3⌉ = 43 base64url chars, padding stripped).
// Tight by design — any other length indicates a non-spec client.
var pathIDRegex = regexp.MustCompile(`^nxc_[A-Za-z0-9_-]{43}$`)

// uuidv7Regex pins the UUIDv7 wire format: 7 in the version nibble,
// 0b10xx in the variant nibble.
var uuidv7Regex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// OuterEnvelope is the cleartext-routing layer. All fields are required
// at v1.
type OuterEnvelope struct {
	Version          string `json:"version"`
	MsgID            string `json:"msg_id"`
	Ts               string `json:"ts"`
	PathID           string `json:"path_id"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	Ciphertext       string `json:"ciphertext"`
}

// Verifier resolves an inbound request to one of the paired identities
// by checking the X-Nexus-Signature header. Returning an empty pubkey
// signals the signature did not verify against either pair member.
//
// The signed bytes depend on the endpoint: PUT signs canonical JSON of
// the outer envelope; GET signs path+query; POST /ack signs the path.
// The handler produces those bytes; Verifier just matches them against
// pair identities.
type Verifier interface {
	// Identify returns the pubkey of the caller (requester-side or
	// owner-side) whose signature verifies over message. Empty pubkey +
	// nil error = unauthenticated (handler translates to 401). Error =
	// driver-level failure; handler translates to 500.
	Identify(ctx context.Context, pair storage.Pair, signatureB64 string, message []byte) (pubkey string, err error)
}

// StubVerifier always fails verification. Used until Part 2.5 wires real
// signature checking. Explicitly fail-closed so a partial deployment
// doesn't silently accept unsigned traffic.
type StubVerifier struct{}

func (StubVerifier) Identify(context.Context, storage.Pair, string, []byte) (string, error) {
	return "", nil
}

// Handler holds the dependencies needed to serve mailbox routes.
type Handler struct {
	Store    storage.Storage
	Verifier Verifier
	// Clock lets tests pin time. Use time.Now if nil.
	Clock func() time.Time
}

func (h *Handler) now() time.Time {
	if h.Clock != nil {
		return h.Clock()
	}
	return time.Now()
}

// Routes returns an http.Handler that dispatches mailbox URLs. Called
// from main to mount /mailbox/* under the root mux.
func (h *Handler) Routes() http.Handler {
	return http.HandlerFunc(h.dispatch)
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request) {
	// URL shapes:
	//   /mailbox/:pathId            — PUT (append) or GET (list)
	//   /mailbox/:pathId/ack        — POST (evict)
	trimmed := strings.TrimPrefix(r.URL.Path, "/mailbox/")
	if trimmed == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing_path_id", http.StatusBadRequest)
		return
	}
	pathID := parts[0]
	if !pathIDRegex.MatchString(pathID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_path_id"})
		return
	}

	switch len(parts) {
	case 1:
		switch r.Method {
		case http.MethodPut:
			h.put(w, r, pathID)
		case http.MethodGet:
			h.get(w, r, pathID)
		default:
			w.Header().Set("Allow", "PUT, GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case 2:
		if parts[1] == "ack" && r.Method == http.MethodPost {
			h.ack(w, r, pathID)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

// put handles PUT /mailbox/:pathId. Validates schema, replay window,
// ciphertext hash integrity, signature, pair existence, duplicate msg_id.
func (h *Handler) put(w http.ResponseWriter, r *http.Request, pathID string) {
	ctx := r.Context()

	pair, err := h.Store.GetPair(ctx, pathID)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pair_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20)) // 2 MiB cap — 1 MiB body plus envelope overhead
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body_read_failed"})
		return
	}

	var env OuterEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if !validEnvelopeSchema(env) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_envelope"})
		return
	}
	if env.PathID != pathID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path_id_mismatch"})
		return
	}
	if !uuidv7Regex.MatchString(env.MsgID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_msg_id"})
		return
	}
	if !tsInWindow(env.Ts, h.now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ts_out_of_window"})
		return
	}

	ctBytes, err := base64urlDecode(env.Ciphertext)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ciphertext_not_base64url"})
		return
	}
	digest := sha256.Sum256(ctBytes)
	if hex.EncodeToString(digest[:]) != env.CiphertextSHA256 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ciphertext_hash_mismatch"})
		return
	}

	// Verify signature over server-recanonicalized JSON. If the client's
	// canonicalization was correct, this matches byte-for-byte; if it
	// wasn't, re-canonicalization gives structurally-equivalent JSON a
	// chance to verify rather than silently 401-ing on whitespace drift.
	canonical, err := canonicalJSON(env)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "canonicalize_failed"})
		return
	}
	sigHeader := r.Header.Get("X-Nexus-Signature")
	sender, err := h.Verifier.Identify(ctx, pair, sigHeader, canonical)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verifier_error"})
		return
	}
	if sender == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature_invalid"})
		return
	}

	direction := directionFrom(pair, sender)
	if direction == "" {
		// Verifier returned a pubkey that isn't one of the pair's halves —
		// should be impossible if Verifier honours its contract, but fail
		// closed.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sender_not_in_pair"})
		return
	}

	err = h.Store.InsertEnvelope(ctx, storage.Envelope{
		MsgID:      env.MsgID,
		PathID:     pathID,
		Direction:  direction,
		ReceivedAt: h.now(),
		Ciphertext: env.Ciphertext,
		Signature:  sigHeader,
		OuterJSON:  string(body),
	})
	if errors.Is(err, storage.ErrDuplicate) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "duplicate_msg_id"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"msg_id": env.MsgID})
}

// get handles GET /mailbox/:pathId?since=<msg_id>. Caller signs
// path+query; response is the envelopes addressed to the caller.
func (h *Handler) get(w http.ResponseWriter, r *http.Request, pathID string) {
	ctx := r.Context()

	pair, err := h.Store.GetPair(ctx, pathID)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pair_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}

	sigHeader := r.Header.Get("X-Nexus-Signature")
	signedBytes := []byte(r.URL.Path)
	if r.URL.RawQuery != "" {
		signedBytes = []byte(r.URL.Path + "?" + r.URL.RawQuery)
	}
	caller, err := h.Verifier.Identify(ctx, pair, sigHeader, signedBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verifier_error"})
		return
	}
	if caller == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature_invalid"})
		return
	}

	since := r.URL.Query().Get("since")
	if since != "" && !uuidv7Regex.MatchString(since) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_since"})
		return
	}

	// Envelopes addressed TO the caller — opposite of the sender's
	// direction. Requester sends A→B, reads B→A; owner sends B→A, reads
	// A→B.
	readDirection := readDirectionFor(pair, caller)
	if readDirection == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "caller_not_in_pair"})
		return
	}

	envelopes, err := h.Store.ListEnvelopes(ctx, pathID, readDirection, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}

	outer := make([]json.RawMessage, 0, len(envelopes))
	var cursor string
	for _, e := range envelopes {
		outer = append(outer, json.RawMessage(e.OuterJSON))
		cursor = e.MsgID
	}
	resp := struct {
		Envelopes []json.RawMessage `json:"envelopes"`
		Cursor    *string           `json:"cursor"`
	}{Envelopes: outer}
	if cursor != "" {
		resp.Cursor = &cursor
	}
	writeJSON(w, http.StatusOK, resp)
}

// ack handles POST /mailbox/:pathId/ack. Caller signs path. Only evicts
// envelopes addressed to caller.
func (h *Handler) ack(w http.ResponseWriter, r *http.Request, pathID string) {
	ctx := r.Context()

	pair, err := h.Store.GetPair(ctx, pathID)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pair_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}

	sigHeader := r.Header.Get("X-Nexus-Signature")
	caller, err := h.Verifier.Identify(ctx, pair, sigHeader, []byte(r.URL.Path))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verifier_error"})
		return
	}
	if caller == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature_invalid"})
		return
	}

	var body struct {
		IDs []string `json:"ids"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body_read_failed"})
		return
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if len(body.IDs) == 0 {
		writeJSON(w, http.StatusOK, map[string]int{"evicted": 0})
		return
	}
	if len(body.IDs) > maxAckBatch {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "too_many_ids", "max": maxAckBatch})
		return
	}

	// Only evict envelopes addressed to the caller (one side cannot
	// delete the other's inbox). The direction filter is built into the
	// deletion query: we delete by (pathID, msg_id) but first narrow to
	// the caller's read direction using a separate list.
	readDirection := readDirectionFor(pair, caller)
	if readDirection == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "caller_not_in_pair"})
		return
	}

	// Fetch the caller's envelopes in the given IDs, then delete those.
	// Cheaper than adding a direction-aware delete method to storage for
	// now. If this shows up in profiling, Part 2.4+ can add it.
	toDelete := make([]string, 0, len(body.IDs))
	// Build a set for O(1) membership check.
	idSet := make(map[string]struct{}, len(body.IDs))
	for _, id := range body.IDs {
		idSet[id] = struct{}{}
	}
	// Walk caller's inbox; filter by requested IDs.
	mine, err := h.Store.ListEnvelopes(ctx, pathID, readDirection, "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}
	for _, e := range mine {
		if _, ok := idSet[e.MsgID]; ok {
			toDelete = append(toDelete, e.MsgID)
		}
	}

	evicted, err := h.Store.DeleteEnvelopesByMsgID(ctx, pathID, toDelete)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"evicted": evicted})
}

// validEnvelopeSchema checks presence of every required v1 field. Go's
// JSON unmarshal leaves missing-string fields as "", so empty == missing.
func validEnvelopeSchema(e OuterEnvelope) bool {
	return e.Version == "1" &&
		e.MsgID != "" &&
		e.Ts != "" &&
		e.PathID != "" &&
		e.CiphertextSHA256 != "" &&
		e.Ciphertext != ""
}

// tsInWindow enforces the ±5 min replay window against a caller-supplied
// clock. Parses ISO 8601.
func tsInWindow(ts string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t2, err2 := time.Parse("2006-01-02T15:04:05Z", ts)
		if err2 != nil {
			return false
		}
		t = t2
	}
	d := now.Sub(t)
	if d < 0 {
		d = -d
	}
	return d <= replayWindow
}

// base64urlDecode handles both padded and unpadded base64url input. The
// spec uses unpadded, but lenient decode avoids brittle interop.
func base64urlDecode(s string) ([]byte, error) {
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

// directionFrom returns the direction a PUT from sender travels.
// Requester half → A_to_B, owner half → B_to_A.
func directionFrom(pair storage.Pair, senderPubkey string) storage.Direction {
	switch senderPubkey {
	case pair.RequesterPubkey:
		return storage.AToB
	case pair.OwnerPubkey:
		return storage.BToA
	default:
		return ""
	}
}

// readDirectionFor returns the direction of envelopes ADDRESSED to
// caller. Requester reads B_to_A, owner reads A_to_B.
func readDirectionFor(pair storage.Pair, callerPubkey string) storage.Direction {
	switch callerPubkey {
	case pair.RequesterPubkey:
		return storage.BToA
	case pair.OwnerPubkey:
		return storage.AToB
	default:
		return ""
	}
}

// canonicalJSON produces RFC 8785 canonical JSON of the outer envelope.
// The struct layout fixes field order (alphabetical by JSON tag) — JCS
// requires lexicographic key order, which for this fixed 6-field struct
// is trivially achieved by declaration order. All values are ASCII-only
// strings (base64url, hex, UUID, ISO 8601), so no Unicode-escaping edge
// cases. HTML escaping disabled via SetEscapeHTML(false) — Go's default
// escapes `<`, `>`, `&` as \u00XX which TS JSON.stringify does not, and
// that divergence would break signature verification across runtimes.
// If future revisions add free-text fields, revisit: a full JCS library
// will be needed for Unicode normalization.
func canonicalJSON(e OuterEnvelope) ([]byte, error) {
	canonical := struct {
		Ciphertext       string `json:"ciphertext"`
		CiphertextSHA256 string `json:"ciphertext_sha256"`
		MsgID            string `json:"msg_id"`
		PathID           string `json:"path_id"`
		Ts               string `json:"ts"`
		Version          string `json:"version"`
	}{
		Ciphertext:       e.Ciphertext,
		CiphertextSHA256: e.CiphertextSHA256,
		MsgID:            e.MsgID,
		PathID:           e.PathID,
		Ts:               e.Ts,
		Version:          e.Version,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(canonical); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a trailing newline; JCS forbids it.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// writeJSON is a shared response helper. Silences write errors — by the
// time we're writing a body the client may have disconnected, and
// there's nothing useful the handler can do about it.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
