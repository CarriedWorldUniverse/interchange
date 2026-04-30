// Package pairflow handles the staged-approval pair registration flow:
//
//   POST /pair/request               — requester submits their half
//   GET  /pair/requests/:id          — requester polls for decision
//   GET  /pair/requests?status=...   — owner lists pending (tailnet-only)
//   POST /pair/requests/:id/approve  — owner submits their half (tailnet-only)
//   POST /pair/requests/:id/deny     — owner rejects (tailnet-only)
//
// The package exposes two HTTP handlers: PublicRoutes for /pair/request
// and /pair/requests/:id, and OwnerRoutes for approve/deny/list. main
// mounts these on two different listeners — public on the Funnel-exposed
// port, owner on a tailnet-only interface — so the operator-approval
// invariant is enforced at the network layer, not via auth headers.
//
// v1 accepts sig_alg="ed25519" only (anvil #7828, #7841). P-256
// signing is aspirational and rejected at /pair/request with a clear
// error rather than silently failing self-sig verification later.
package pairflow

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/nexus-cw/interchange/internal/storage"
)

const (
	replayWindow = 5 * time.Minute
	requestTTL   = 24 * time.Hour
	maxBodySize  = 64 * 1024
)

// uuidRegex matches request_id (UUIDv4 minted server-side).
var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RequestIDGen mints new request_id strings. Default uses crypto/rand
// for UUIDv4 shape. Tests inject deterministic generators.
type RequestIDGen func() string

// Handler bundles dependencies for the pair-flow endpoints.
type Handler struct {
	Store       storage.Storage
	Clock       func() time.Time // defaults to time.Now
	GenID       RequestIDGen     // defaults to crypto/rand UUIDv4
	OwnerSecret string           // optional shared-secret for owner endpoints; empty = no auth beyond tailnet binding
}

func (h *Handler) now() time.Time {
	if h.Clock != nil {
		return h.Clock()
	}
	return time.Now()
}

func (h *Handler) genID() string {
	if h.GenID != nil {
		return h.GenID()
	}
	return newUUIDv4()
}

// PublicRoutes returns an http.Handler for the Funnel-exposed surface:
// POST /pair/request, GET /pair/requests/:id.
func (h *Handler) PublicRoutes() http.Handler {
	return http.HandlerFunc(h.dispatchPublic)
}

// OwnerRoutes returns an http.Handler for the tailnet-only surface:
// GET /pair/requests, POST /pair/requests/:id/approve,
// POST /pair/requests/:id/deny.
func (h *Handler) OwnerRoutes() http.Handler {
	return http.HandlerFunc(h.dispatchOwner)
}

func (h *Handler) dispatchPublic(w http.ResponseWriter, r *http.Request) {
	// Expire stale pending requests before every query — idempotent,
	// cheap, keeps GET /pair/requests/:id accurate without a separate
	// sweep timer firing inline.
	_, _ = h.Store.ExpirePendingRequests(r.Context(), h.now())

	path := strings.TrimPrefix(r.URL.Path, "/pair/")
	if path == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(path, "/")

	// /pair/request — submit a new request
	if len(parts) == 1 && parts[0] == "request" && r.Method == http.MethodPost {
		h.createRequest(w, r)
		return
	}
	// /pair/requests/:id — poll status
	if len(parts) == 2 && parts[0] == "requests" && parts[1] != "" && r.Method == http.MethodGet {
		h.getRequestStatus(w, r, parts[1])
		return
	}

	http.NotFound(w, r)
}

func (h *Handler) dispatchOwner(w http.ResponseWriter, r *http.Request) {
	// Optional shared-secret check layered on top of tailnet binding.
	// If OwnerSecret is set, require matching X-Owner-Secret header.
	// Tailnet binding is the primary control — this is belt-and-suspenders.
	//
	// Constant-time compare: a process on the same host as the tailnet
	// listener can time responses to brute-force the secret one byte at
	// a time with string-equality compare. subtle.ConstantTimeCompare
	// returns 1 iff the byte slices are equal length AND equal content.
	if h.OwnerSecret != "" {
		got := r.Header.Get("X-Owner-Secret")
		if subtle.ConstantTimeCompare([]byte(got), []byte(h.OwnerSecret)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "owner_auth_required"})
			return
		}
	}

	_, _ = h.Store.ExpirePendingRequests(r.Context(), h.now())

	path := strings.TrimPrefix(r.URL.Path, "/pair/")
	if path == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(path, "/")

	// /pair/requests — list (owner only)
	if len(parts) == 1 && parts[0] == "requests" && r.Method == http.MethodGet {
		h.listPending(w, r)
		return
	}
	// /pair/requests/:id/approve or /deny
	if len(parts) == 3 && parts[0] == "requests" && parts[2] != "" && r.Method == http.MethodPost {
		id := parts[1]
		switch parts[2] {
		case "approve":
			h.approve(w, r, id)
			return
		case "deny":
			h.deny(w, r, id)
			return
		}
	}

	http.NotFound(w, r)
}

// half is the parsed form of a requester-or-owner submission.
//
// dh_alg + dh_pubkey are v2 additions (optional in the parser to keep
// backwards compatibility with v1 callers during the transition). When
// present, they are covered by the v2 self-sig preimage. The relay is
// curve-agnostic — it does not enforce that dh_alg matches between
// requester and owner; clients (casket.Channel.Pair) detect mismatches
// at local activation with a clearer error.
type half struct {
	NexusID   string `json:"nexus_id"`
	SigAlg    string `json:"sig_alg"`
	Pubkey    string `json:"pubkey"`    // base64url wire-format Ed25519 (32 bytes raw)
	DhAlg     string `json:"dh_alg,omitempty"`     // "P-256" or "X25519" — v2
	DhPubkey  string `json:"dh_pubkey,omitempty"`  // base64url ECDH pubkey — v2
	Endpoint  string `json:"endpoint"`  // optional
	Nonce     string `json:"nonce"`     // base64url 16+ bytes
	Ts        string `json:"ts"`        // ISO 8601 UTC
	SelfSig   string `json:"self_sig"`  // base64url detached sig over canonical bytes
	pubkeyRaw []byte // decoded on parse
}

// parseHalf validates the half's schema and decodes the pubkey. Does
// not verify the self-sig — caller does that.
func parseHalf(in half) (half, string) {
	if in.NexusID == "" || in.SigAlg == "" || in.Pubkey == "" || in.Nonce == "" ||
		in.Ts == "" || in.SelfSig == "" {
		return half{}, "missing_fields"
	}
	// Length caps on free-form strings. Stops a requester from spamming
	// 64 KB nexus_id / endpoint values into the DB and dashboard surface.
	if len(in.NexusID) > 256 {
		return half{}, "nexus_id_too_long"
	}
	if len(in.Endpoint) > 1024 {
		return half{}, "endpoint_too_long"
	}
	// v1: Ed25519 only. p256 rejected explicitly here (NOT silently via
	// self-sig failure) so the error message is actionable.
	if in.SigAlg != "ed25519" {
		return half{}, "unsupported_sig_alg"
	}
	pub, err := decodeB64URL(in.Pubkey)
	if err != nil {
		return half{}, "pubkey_not_base64url"
	}
	if len(pub) != ed25519.PublicKeySize {
		return half{}, "pubkey_length"
	}
	in.pubkeyRaw = pub

	// v2: if dh_alg or dh_pubkey is present, validate basic shape. Both
	// must be present together. Curve choice (P-256 vs X25519) is not
	// enforced against any allowlist here — relay stays curve-agnostic.
	if in.DhAlg != "" || in.DhPubkey != "" {
		if in.DhAlg == "" || in.DhPubkey == "" {
			return half{}, "dh_alg_or_dh_pubkey_missing"
		}
		if len(in.DhAlg) > 32 {
			return half{}, "dh_alg_too_long"
		}
		if len(in.DhPubkey) > 256 {
			return half{}, "dh_pubkey_too_long"
		}
		if _, err := decodeB64URL(in.DhPubkey); err != nil {
			return half{}, "dh_pubkey_not_base64url"
		}
	}
	return in, ""
}

// canonicalBytesV1 builds the deprecated v1 self-sig preimage:
// "v1\n<nexus_id>\n<sig_alg>\n<pubkey>\n<endpoint>\n<nonce>\n<ts>",
// no trailing newline. Accepted during the v1→v2 transition.
func canonicalBytesV1(h half) []byte {
	return []byte(strings.Join([]string{
		"v1",
		h.NexusID,
		h.SigAlg,
		h.Pubkey,
		h.Endpoint,
		h.Nonce,
		h.Ts,
	}, "\n"))
}

// canonicalBytesV2 builds the current v2 self-sig preimage:
// "v2\n<nexus_id>\n<sig_alg>\n<pubkey>\n<dh_alg>\n<dh_pubkey>\n<endpoint>\n<nonce>\n<ts>",
// no trailing newline. Includes ECDH material under signature coverage
// so a relay or wire observer cannot substitute dh_pubkey without
// invalidating the signature.
func canonicalBytesV2(h half) []byte {
	return []byte(strings.Join([]string{
		"v2",
		h.NexusID,
		h.SigAlg,
		h.Pubkey,
		h.DhAlg,
		h.DhPubkey,
		h.Endpoint,
		h.Nonce,
		h.Ts,
	}, "\n"))
}

// verifySelfSig checks the half's self_sig against its own pubkey,
// trying the v2 preimage first when dh_alg is set. If the v2 verify
// fails (or dh_alg is empty), falls back to v1. New halves should be
// signed with v2; v1 is accepted only during the migration window.
//
// Important: a half that carries dh_alg + dh_pubkey but signs with the
// v1 preimage leaves the dh_pubkey out of signature coverage — open to
// substitution. We REJECT that case explicitly: if dh_pubkey is present
// the signature MUST verify against v2 (and only v2). Otherwise we
// would silently accept a half whose ECDH key is unsigned.
func verifySelfSig(h half) bool {
	sig, err := decodeB64URL(h.SelfSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	pub := ed25519.PublicKey(h.pubkeyRaw)

	if h.DhPubkey != "" {
		// v2 mandatory: dh_pubkey must be in signature coverage.
		return ed25519.Verify(pub, canonicalBytesV2(h), sig)
	}
	// v1 only: legacy half without ECDH material.
	return ed25519.Verify(pub, canonicalBytesV1(h), sig)
}

// tsInWindow enforces the ±5min replay window.
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

// createRequest handles POST /pair/request.
func (h *Handler) createRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TargetNexusID string `json:"target_nexus_id"`
		Requester     half   `json:"requester"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body_read_failed"})
		return
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if body.TargetNexusID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_target"})
		return
	}
	if len(body.TargetNexusID) > 256 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_nexus_id_too_long"})
		return
	}
	parsed, errCode := parseHalf(body.Requester)
	if errCode != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errCode})
		return
	}
	if !tsInWindow(parsed.Ts, h.now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ts_out_of_window"})
		return
	}
	if !verifySelfSig(parsed) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_self_sig"})
		return
	}

	requesterJSON, _ := serializeHalf(parsed)
	requestID := h.genID()
	now := h.now()
	err = h.Store.InsertPairRequest(r.Context(), storage.PairRequest{
		RequestID:     requestID,
		Status:        storage.StatusPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(requestTTL),
		RequesterJSON: string(requesterJSON),
		TargetNexusID: body.TargetNexusID,
	})
	if errors.Is(err, storage.ErrDuplicate) {
		// Generator collision — shouldn't happen with real UUIDv4, but
		// if it does, surface not silently retry.
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "request_id_collision"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"request_id": requestID,
		"status":     string(storage.StatusPending),
		"expires_at": now.Add(requestTTL).UTC().Format(time.RFC3339),
	})
}

// getRequestStatus handles GET /pair/requests/:id.
func (h *Handler) getRequestStatus(w http.ResponseWriter, r *http.Request, requestID string) {
	if !uuidRegex.MatchString(requestID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request_id"})
		return
	}
	req, err := h.Store.GetPairRequest(r.Context(), requestID)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}
	resp := map[string]any{
		"request_id": req.RequestID,
		"status":     string(req.Status),
	}
	if req.PathID != "" {
		resp["path_id"] = req.PathID
	}
	// v2: when status=approved, surface the OWNER's half so the
	// requester can locally instantiate a paired channel without an
	// out-of-band PairingToken exchange. The owner's half was stored
	// at approve-time in OwnerJSON. Stays absent for pending/denied/
	// expired states.
	if req.Status == storage.StatusApproved && req.OwnerJSON != "" {
		var owner half
		if err := json.Unmarshal([]byte(req.OwnerJSON), &owner); err == nil {
			resp["owner_half"] = halfToWire(owner)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// halfToWire returns the public-fields-only view of a half suitable for
// surfacing in API responses. Strips the internal pubkeyRaw scratch
// field; preserves all wire-shape fields (including v2 dh_alg + dh_pubkey
// when set).
func halfToWire(h half) map[string]string {
	out := map[string]string{
		"nexus_id": h.NexusID,
		"sig_alg":  h.SigAlg,
		"pubkey":   h.Pubkey,
		"endpoint": h.Endpoint,
		"nonce":    h.Nonce,
		"ts":       h.Ts,
		"self_sig": h.SelfSig,
	}
	if h.DhAlg != "" {
		out["dh_alg"] = h.DhAlg
	}
	if h.DhPubkey != "" {
		out["dh_pubkey"] = h.DhPubkey
	}
	return out
}

// listPending handles GET /pair/requests?status=pending (owner only).
func (h *Handler) listPending(w http.ResponseWriter, r *http.Request) {
	wantStatus := r.URL.Query().Get("status")
	if wantStatus == "" {
		wantStatus = string(storage.StatusPending)
	}
	// v1: only "pending" is queryable. Other filters would require new
	// storage methods; callers wanting history can fetch by request_id.
	if wantStatus != string(storage.StatusPending) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status_filter_unsupported", "only": "pending"})
		return
	}
	reqs, err := h.Store.ListPendingPairRequests(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}
	out := make([]map[string]any, 0, len(reqs))
	for _, req := range reqs {
		rendered := map[string]any{
			"request_id":      req.RequestID,
			"status":          string(req.Status),
			"created_at":      req.CreatedAt.UTC().Format(time.RFC3339),
			"target_nexus_id": req.TargetNexusID,
		}
		// Surface a trimmed requester view — drop the full self-sig
		// for cleaner dashboards; operator sees enough to decide.
		// dh_alg + dh_pubkey are surfaced when present (v2 halves) so
		// the operator can distinguish v1 vs v2 requesters at a glance
		// before approving. omitempty preserved — v1 halves carry no
		// ECDH material and the trimmed view stays clean.
		var r half
		if err := json.Unmarshal([]byte(req.RequesterJSON), &r); err == nil {
			requesterView := map[string]string{
				"nexus_id": r.NexusID,
				"sig_alg":  r.SigAlg,
				"pubkey":   r.Pubkey,
				"endpoint": r.Endpoint,
			}
			if r.DhAlg != "" {
				requesterView["dh_alg"] = r.DhAlg
			}
			if r.DhPubkey != "" {
				requesterView["dh_pubkey"] = r.DhPubkey
			}
			rendered["requester"] = requesterView
		}
		out = append(out, rendered)
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

// approve handles POST /pair/requests/:id/approve.
func (h *Handler) approve(w http.ResponseWriter, r *http.Request, requestID string) {
	if !uuidRegex.MatchString(requestID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request_id"})
		return
	}

	var body struct {
		Owner half `json:"owner"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body_read_failed"})
		return
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	// Load the pending request to recover the requester half.
	req, err := h.Store.GetPairRequest(r.Context(), requestID)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}
	// If the request is already approved with the same pair as we'd
	// compute now, treat this call as idempotent success. If denied/
	// expired/approved-with-different-pair, surface conflict so the
	// caller learns why.
	if req.Status != storage.StatusPending {
		if req.Status == storage.StatusApproved && req.PathID != "" {
			// Parse owner half to verify the caller holds the key they
			// claim. Without this the idempotency path would accept
			// ANY post to an already-approved request.
			owner, errCode := parseHalf(body.Owner)
			if errCode == "" && verifySelfSig(owner) {
				existing, gerr := h.Store.GetPair(r.Context(), req.PathID)
				if gerr == nil && existing.OwnerPubkey == owner.Pubkey {
					writeJSON(w, http.StatusOK, map[string]any{
						"request_id":     requestID,
						"status":         "approved",
						"path_id":        req.PathID,
						"requester_half": parsedRequesterHalf(req.RequesterJSON),
					})
					return
				}
			}
		}
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "request_not_pending", "status": string(req.Status),
		})
		return
	}

	var requester half
	if err := json.Unmarshal([]byte(req.RequesterJSON), &requester); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "stored_requester_corrupt"})
		return
	}
	requester.pubkeyRaw, _ = decodeB64URL(requester.Pubkey) // already validated at create time

	// Parse + validate owner half.
	owner, errCode := parseHalf(body.Owner)
	if errCode != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errCode})
		return
	}
	// Both sides MUST use the same sig_alg. At v1 this is always
	// ed25519 (parseHalf already enforces), but the explicit check is
	// cheap and documents the invariant.
	if owner.SigAlg != requester.SigAlg {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sig_alg_mismatch"})
		return
	}
	if !tsInWindow(owner.Ts, h.now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ts_out_of_window"})
		return
	}
	if !verifySelfSig(owner) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_self_sig"})
		return
	}

	// Compute pathId: "nxc_" + base64url(sha256(sort(reqPub, ownPub))).
	pathID := computePathID(requester.pubkeyRaw, owner.pubkeyRaw)

	// Insert the pair first. If ErrDuplicate, a previous approval for
	// the same pair already activated — surface as conflict rather than
	// silently continuing with a pair we didn't mint.
	err = h.Store.InsertPair(r.Context(), storage.Pair{
		PathID:            pathID,
		RequesterID:       requester.NexusID,
		RequesterPubkey:   requester.Pubkey,
		RequesterDHPubkey: "", // filled by spec DH field when clients carry it; not used by interchange verify path
		OwnerID:           owner.NexusID,
		OwnerPubkey:       owner.Pubkey,
		OwnerDHPubkey:     "",
		SigAlg:            requester.SigAlg,
		DhAlg:             "P-256", // default; interchange doesn't use this field, clients do
		ActivatedAt:       h.now(),
	})
	if errors.Is(err, storage.ErrDuplicate) {
		// Pair exists — probably the request was already approved in a
		// concurrent call. Check: if the existing pair matches, treat
		// as idempotent success; otherwise conflict.
		existing, gerr := h.Store.GetPair(r.Context(), pathID)
		if gerr == nil && existing.RequesterPubkey == requester.Pubkey && existing.OwnerPubkey == owner.Pubkey {
			// Update pair request to approved to keep state consistent.
			_ = h.Store.UpdatePairRequestStatus(r.Context(), requestID, storage.StatusApproved, string(raw), pathID)
			writeJSON(w, http.StatusOK, map[string]any{
				"request_id":     requestID,
				"status":         "approved",
				"path_id":        pathID,
				"requester_half": halfToWire(requester),
			})
			return
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": "pair_conflict"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}

	// Now claim the request → approved. If UpdatePairRequestStatus
	// returns ErrConflict, someone denied between our pending read and
	// our approve write — rare but possible. Surface as 409.
	ownerJSON, _ := serializeHalf(owner)
	err = h.Store.UpdatePairRequestStatus(r.Context(), requestID, storage.StatusApproved, string(ownerJSON), pathID)
	if errors.Is(err, storage.ErrConflict) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "request_not_pending_concurrent"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"request_id":     requestID,
		"status":         "approved",
		"path_id":        pathID,
		"requester_half": halfToWire(requester),
	})
}

// parsedRequesterHalf is a helper that decodes the stored requester
// JSON to a wire-shape map. Returns an empty map on parse failure
// (the surrounding response is still useful even if the half is
// recovered as empty — the requester can fetch via status poll).
func parsedRequesterHalf(stored string) map[string]string {
	var h half
	if err := json.Unmarshal([]byte(stored), &h); err != nil {
		return map[string]string{}
	}
	return halfToWire(h)
}

// deny handles POST /pair/requests/:id/deny.
func (h *Handler) deny(w http.ResponseWriter, r *http.Request, requestID string) {
	if !uuidRegex.MatchString(requestID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request_id"})
		return
	}
	err := h.Store.UpdatePairRequestStatus(r.Context(), requestID, storage.StatusDenied, "", "")
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_not_found"})
		return
	}
	if errors.Is(err, storage.ErrConflict) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "request_not_pending"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"request_id": requestID,
		"status":     string(storage.StatusDenied),
	})
}

// computePathID returns "nxc_" + base64url(sha256(sort(a, b))).
// Bytewise ascending sort of the raw public keys so both sides derive
// the same pathId regardless of which is "requester" and which is "owner".
func computePathID(a, b []byte) string {
	first, second := a, b
	if bytesLess(b, a) {
		first, second = b, a
	}
	h := sha256.New()
	h.Write(first)
	h.Write(second)
	return "nxc_" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// bytesLess returns a < b by lexicographic byte comparison.
func bytesLess(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// serializeHalf JSON-encodes the half back into the stored-record form,
// stripping the private pubkeyRaw cache field.
func serializeHalf(h half) ([]byte, error) {
	// Persist all wire-shape fields, including v2 ECDH material when
	// present. Storage holds the canonical form so it can be returned
	// later as `requester_half` / `owner_half` in approve/poll
	// responses without re-deriving from the raw request body.
	wire := struct {
		NexusID  string `json:"nexus_id"`
		SigAlg   string `json:"sig_alg"`
		Pubkey   string `json:"pubkey"`
		DhAlg    string `json:"dh_alg,omitempty"`
		DhPubkey string `json:"dh_pubkey,omitempty"`
		Endpoint string `json:"endpoint"`
		Nonce    string `json:"nonce"`
		Ts       string `json:"ts"`
		SelfSig  string `json:"self_sig"`
	}{
		NexusID:  h.NexusID,
		SigAlg:   h.SigAlg,
		Pubkey:   h.Pubkey,
		DhAlg:    h.DhAlg,
		DhPubkey: h.DhPubkey,
		Endpoint: h.Endpoint,
		Nonce:    h.Nonce,
		Ts:       h.Ts,
		SelfSig:  h.SelfSig,
	}
	return json.Marshal(wire)
}

// decodeB64URL tolerates padded and unpadded.
func decodeB64URL(s string) ([]byte, error) {
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

// newUUIDv4 mints a RFC 4122 v4 UUID using crypto/rand.
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should not fail; if it does, panic is appropriate —
		// we can't safely mint request IDs without entropy.
		panic(fmt.Errorf("pairflow: random read failed: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// writeJSON is the shared response helper.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
