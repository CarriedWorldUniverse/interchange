// Package crypto implements the real mailbox.Verifier using stdlib
// Ed25519.
//
// The interchange is a dumb relay: it verifies incoming signatures
// against the pubkeys registered at pairing time, but does not hold any
// private keys and does not need the full casket Channel abstraction.
// Clients (Nexus frames) use casket-go for key material and signing;
// the interchange only verifies.
//
// v1 supports Ed25519 only — per anvil #7828 and #7841, p256 is an
// aspirational signing path not yet implemented on either side. A pair
// whose sig_alg is not "ed25519" is rejected at /pair/request time in
// Part 2.5b; this package validates the assumption and returns a clear
// error for any other value that somehow slipped through.
package crypto

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/CarriedWorldUniverse/interchange/internal/mailbox"
	"github.com/CarriedWorldUniverse/interchange/internal/storage"
)

// ErrUnsupportedAlgorithm is returned when a registered pair claims a
// sig_alg other than "ed25519". At v1 the interchange rejects these at
// /pair/request; this guard catches anything that reaches the verifier
// despite that check.
var ErrUnsupportedAlgorithm = errors.New("crypto: unsupported sig_alg")

// EdVerifier is a mailbox.Verifier that checks Ed25519 signatures
// against the pubkeys stored with the pair.
//
// Zero value is ready to use. Pulls no state; the Identify method
// looks up pubkeys from the storage.Pair passed in by the handler.
type EdVerifier struct{}

// Identify walks both halves of the pair and returns the pubkey of
// whichever one's signature verifies. Returns ("", nil) when the
// signature doesn't verify against either — handler maps that to 401.
//
// Returns an error only on malformed inputs or unsupported algorithms
// (those map to 500 in the handler, because they signal drift between
// pair registration and verification rather than a caller problem).
func (EdVerifier) Identify(_ context.Context, pair storage.Pair, signatureB64 string, message []byte) (string, error) {
	if pair.SigAlg != "ed25519" {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, pair.SigAlg)
	}
	if signatureB64 == "" {
		return "", nil
	}

	sig, err := decodeB64URL(signatureB64)
	if err != nil {
		// Malformed signature is a 401 not a 500 — caller bug, not ours.
		return "", nil
	}
	if len(sig) != ed25519.SignatureSize {
		return "", nil
	}

	// Try the requester half first, then the owner half. Both are
	// equally likely senders; verification is O(1) per attempt.
	for _, half := range []struct {
		pubkey string
	}{
		{pair.RequesterPubkey},
		{pair.OwnerPubkey},
	} {
		pubBytes, err := decodeB64URL(half.pubkey)
		if err != nil {
			// Stored pubkey is malformed — this is a data-integrity
			// error, surface it so the operator notices.
			return "", fmt.Errorf("crypto: stored pubkey not base64url for pair %s: %w", pair.PathID, err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return "", fmt.Errorf("crypto: stored pubkey wrong size (%d) for pair %s", len(pubBytes), pair.PathID)
		}
		if ed25519.Verify(pubBytes, message, sig) {
			return half.pubkey, nil
		}
	}
	return "", nil
}

// Compile-time check that EdVerifier satisfies the handler's contract.
var _ mailbox.Verifier = EdVerifier{}

// decodeB64URL decodes base64url with or without padding. The spec
// uses unpadded (as casket-go produces), but lenient decode avoids
// interop surprises if some other client happens to pad.
func decodeB64URL(s string) ([]byte, error) {
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}
