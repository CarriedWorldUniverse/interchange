package discovery

// Wire-format examples. Self-consistent: every value derives
// deterministically from two fixed Ed25519 seeds (alice/bob, all-zeros
// and all-ones). External implementers can regenerate them with
// `go test -run TestExamples -update` (see examples_test.go).
//
// Real keys, real signatures over real preimages, real path_id derived
// from real pubkeys. Test material only — these seeds MUST NOT be used
// for any live identity. They exist so an implementer can verify their
// own canonicalization, signing, and pair-half assembly bit-for-bit
// against the doc.

// Examples is the top-level examples block exposed by the discovery
// document. Each sub-document is a complete wire payload an external
// implementer can match byte-for-byte.
type Examples struct {
	Note            string             `json:"note"`
	TestKeys        ExampleTestKeys    `json:"test_keys"`
	PairHalf        ExamplePairHalf    `json:"pair_half"`
	OuterEnvelope   ExampleOuter       `json:"outer_envelope"`
	InnerEnvelope   ExampleInner       `json:"inner_envelope"`
	PathIDDerivation ExamplePathID     `json:"path_id_derivation"`
}

type ExampleTestKeys struct {
	Note            string `json:"note"`
	AliceSeedHex    string `json:"alice_ed25519_seed_hex"`
	AlicePubkeyB64u string `json:"alice_ed25519_pubkey_base64url"`
	BobSeedHex      string `json:"bob_ed25519_seed_hex"`
	BobPubkeyB64u   string `json:"bob_ed25519_pubkey_base64url"`
}

type ExamplePairHalf struct {
	Note string `json:"note"`
	V2   ExamplePairHalfVersion `json:"v2_current"`
	V1   ExamplePairHalfVersion `json:"v1_deprecated"`
}

// ExamplePairHalfVersion is one preimage/signature pair for a given
// preimage version. Both v1 (deprecated, transition support) and v2
// (current) are published so an implementer can validate either.
type ExamplePairHalfVersion struct {
	Note      string            `json:"note"`
	Preimage  string            `json:"self_sig_preimage_lf_separated"`
	Signature string            `json:"self_sig_base64url"`
	WireJSON  map[string]string `json:"wire_json"`
}

type ExampleOuter struct {
	Note             string            `json:"note"`
	CanonicalJSON    string            `json:"canonical_json_with_lf_for_readability"`
	WireBytesNote    string            `json:"wire_bytes_note"`
	CiphertextSHA256 string            `json:"ciphertext_sha256_hex"`
	XNexusSignature  string            `json:"x_nexus_signature_header_value"`
}

type ExampleInner struct {
	Note         string            `json:"note"`
	Plaintext    map[string]any    `json:"plaintext"`
	Encryption   ExampleEncryption `json:"encryption_recipe"`
}

type ExampleEncryption struct {
	Note            string `json:"note"`
	NonceHex        string `json:"nonce_hex_12_bytes"`
	AADNote         string `json:"aad_note"`
	AlgorithmReminder string `json:"algorithm_reminder"`
}

type ExamplePathID struct {
	Note    string `json:"note"`
	Recipe  string `json:"recipe"`
	Result  string `json:"path_id"`
}

// buildExamples constructs the Examples block. Values are computed at
// startup (cheap — fixed inputs, well under 1ms) so a /well-known
// response is a single Marshal of the cached Document.
func buildExamples() Examples {
	return Examples{
		Note: "Wire-format examples derived from two deterministic Ed25519 test seeds. " +
			"Use these to validate your own canonicalization, signing, and pair-half assembly. " +
			"DO NOT use these seeds for any live identity.",

		TestKeys: ExampleTestKeys{
			Note: "Two Ed25519 keypairs from fixed 32-byte seeds. " +
				"Alice = 32 bytes of 0x00. Bob = 32 bytes of 0x01. " +
				"Public keys derived per RFC 8032; provided base64url-encoded (raw, no padding).",
			AliceSeedHex:    aliceSeedHex,
			AlicePubkeyB64u: alicePubB64u,
			BobSeedHex:      bobSeedHex,
			BobPubkeyB64u:   bobPubB64u,
		},

		PairHalf: ExamplePairHalf{
			Note: "A pair-half submitted to POST /pair/request as the requester field, " +
				"or to POST /pair/requests/<id>/approve as the owner field. Two preimage " +
				"versions are published: v2 is current (signature covers dh_alg + dh_pubkey, " +
				"preventing substitution); v1 is deprecated but still accepted by relays " +
				"during the migration window. New implementations MUST write v2.",
			V2: ExamplePairHalfVersion{
				Note: "v2 (current). Preimage covers ECDH material so a relay or wire " +
					"observer cannot swap dh_pubkey without invalidating the signature.",
				Preimage:  examplePreimageV2,
				Signature: examplePreimageSigV2,
				WireJSON: map[string]string{
					"nexus_id":  exampleNexusID,
					"sig_alg":   "ed25519",
					"pubkey":    alicePubB64u,
					"dh_alg":    exampleDhAlg,
					"dh_pubkey": exampleAliceDhPubB64u,
					"endpoint":  exampleEndpoint,
					"nonce":     exampleNonce,
					"ts":        exampleTs,
					"self_sig":  examplePreimageSigV2,
				},
			},
			V1: ExamplePairHalfVersion{
				Note: "v1 (DEPRECATED). dh_pubkey is NOT covered by the signature in v1, " +
					"making it vulnerable to substitution. Provided here only for reference " +
					"during migration. Do not use for new pair attempts.",
				Preimage:  examplePreimageV1,
				Signature: examplePreimageSigV1,
				WireJSON: map[string]string{
					"nexus_id": exampleNexusID,
					"sig_alg":  "ed25519",
					"pubkey":   alicePubB64u,
					"endpoint": exampleEndpoint,
					"nonce":    exampleNonce,
					"ts":       exampleTs,
					"self_sig": examplePreimageSigV1,
				},
			},
		},

		OuterEnvelope: ExampleOuter{
			Note: "The cleartext routing layer transmitted over the wire. " +
				"Sender canonicalizes (RFC 8785), signs the canonical bytes with their Ed25519 key, " +
				"and sends the canonical JSON as the request body with X-Nexus-Signature: <base64url-sig>.",
			CanonicalJSON: exampleOuterCanonical,
			WireBytesNote: "The actual HTTP body is the canonical JSON above WITHOUT the trailing LF added for display. " +
				"Hex of the wire bytes (no terminator): " + exampleOuterWireHex,
			CiphertextSHA256: exampleCiphertextSHA256Hex,
			XNexusSignature:  exampleOuterSig,
		},

		InnerEnvelope: ExampleInner{
			Note: "The plaintext that gets AEAD-sealed before becoming the outer envelope's ciphertext field. " +
				"The recipe shows how to produce the ciphertext from this plaintext.",
			Plaintext: map[string]any{
				"origin_nexus":  "alice-nexus",
				"dest_nexus":    "bob-nexus",
				"kind":          "proposal",
				"in_reply_to":   nil,
				"content_type":  "text/markdown",
				"body":          "Hello, Bob. This is a test message.",
				"attachments":   []any{},
			},
			Encryption: ExampleEncryption{
				Note: "1) Canonicalize the plaintext to bytes per RFC 8785. " +
					"2) Encrypt with AES-256-GCM using HKDF-SHA256(ECDH-shared-secret) as the key. " +
					"3) Prepend the 12-byte nonce to the ciphertext. " +
					"4) AAD = raw 32-byte SHA-256 of the (nonce||ciphertext) bytes about to appear in the outer envelope's ciphertext field, NOT base64 NOT hex.",
				NonceHex:        "000102030405060708090a0b",
				AADNote:         "AAD is bound to the message body itself by hashing the very bytes that will become the outer.ciphertext field. This prevents an attacker from substituting one valid ciphertext for another between two paired peers.",
				AlgorithmReminder: "AES-256-GCM, 12-byte nonce prepended to ciphertext, 16-byte auth tag is implicit in GCM output.",
			},
		},

		PathIDDerivation: ExamplePathID{
			Note: "path_id is computed identically by both peers and the interchange. " +
				"It binds the channel to the two pubkeys.",
			Recipe: "1) Sort the two raw pubkeys (32 bytes each) lexicographically. " +
				"2) Concatenate them in sorted order. " +
				"3) SHA-256 the concatenation. " +
				"4) base64url-encode the digest (raw, no padding). " +
				"5) Prefix with literal 'nxc_'. Result is the path_id.",
			Result: examplePathID,
		},
	}
}
