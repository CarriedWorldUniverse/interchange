package edge_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/CarriedWorldUniverse/interchange/internal/edge"
)

// TestStripClientMetadata removes all cwb-* keys.
func TestStripClientMetadata_RemovesAllCWBKeys(t *testing.T) {
	md := metadata.MD{
		"cwb-org":              []string{"evil-org"},
		"cwb-subject":         []string{"evil-sub"},
		"cwb-kind":             []string{"agent"},
		"cwb-scopes":          []string{"repo:write"},
		"cwb-products":        []string{"commonplace"},
		"cwb-responsible-human": []string{"hacker"},
		"x-other":              []string{"keep-me"},
	}
	edge.StripClientMetadata(md)

	for _, k := range []string{"cwb-org", "cwb-subject", "cwb-kind", "cwb-scopes", "cwb-products", "cwb-responsible-human"} {
		if vals, ok := md[k]; ok && len(vals) > 0 {
			t.Errorf("key %q should be stripped but still has values %v", k, vals)
		}
	}
	// Non-CWB key must survive.
	if got := md.Get("x-other"); len(got) == 0 || got[0] != "keep-me" {
		t.Errorf("x-other should be preserved: %v", md["x-other"])
	}
}

// TestOutgoingContext sets all cwb-* keys from an Identity.
func TestOutgoingContext_SetsIdentityMetadata(t *testing.T) {
	id := edge.Identity{
		Subject:          "agent-42",
		Kind:             "agent",
		Org:              "org-x",
		ResponsibleHuman: "jacinta",
		Scopes:           []string{"repo:read", "kb:write"},
		Products:         []string{"commonplace", "cairn"},
	}
	ctx := edge.OutgoingContext(context.Background(), id)
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("no outgoing metadata on returned context")
	}

	check := func(key, want string) {
		t.Helper()
		vals := md.Get(key)
		if len(vals) == 0 {
			t.Errorf("key %q missing from outgoing metadata", key)
			return
		}
		if vals[0] != want {
			t.Errorf("key %q = %q, want %q", key, vals[0], want)
		}
	}

	check("cwb-org", "org-x")
	check("cwb-subject", "agent-42")
	check("cwb-kind", "agent")
	check("cwb-scopes", "repo:read kb:write")
	check("cwb-products", "commonplace cairn")
	check("cwb-responsible-human", "jacinta")
}

// TestOutgoingContext_NoResponsibleHuman omits the key when empty.
func TestOutgoingContext_NoResponsibleHuman(t *testing.T) {
	id := edge.Identity{Subject: "s", Kind: "agent", Org: "o"}
	ctx := edge.OutgoingContext(context.Background(), id)
	md, _ := metadata.FromOutgoingContext(ctx)
	if vals := md.Get("cwb-responsible-human"); len(vals) > 0 && vals[0] != "" {
		t.Errorf("cwb-responsible-human should be absent for empty ResponsibleHuman, got %v", vals)
	}
}

// TestHasProduct_TrueAndFalse checks product entitlement.
func TestHasProduct_TrueWhenPresent(t *testing.T) {
	id := edge.Identity{Products: []string{"cairn", "commonplace"}}
	if !edge.HasProduct(id, "commonplace") {
		t.Error("HasProduct should be true for 'commonplace'")
	}
	if !edge.HasProduct(id, "cairn") {
		t.Error("HasProduct should be true for 'cairn'")
	}
}

func TestHasProduct_FalseWhenAbsent(t *testing.T) {
	id := edge.Identity{Products: []string{"cairn"}}
	if edge.HasProduct(id, "commonplace") {
		t.Error("HasProduct should be false for 'commonplace' (not in Products)")
	}
	if edge.HasProduct(id, "") {
		t.Error("HasProduct should be false for empty product name")
	}
}

func TestHasProduct_FalseWhenEmpty(t *testing.T) {
	id := edge.Identity{}
	if edge.HasProduct(id, "anything") {
		t.Error("HasProduct should be false when Products is nil")
	}
}

// TestDialPillar_ErrorsOnMissingCertFile ensures DialPillar fails cleanly when cert files don't exist.
func TestDialPillar_ErrorsOnMissingCertFile(t *testing.T) {
	_, err := edge.DialPillar("localhost:9999", "/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/ca.pem")
	if err == nil {
		t.Error("DialPillar should return error when cert files don't exist")
	}
}

// TestDialPillar_ErrorsOnBadCAFile ensures DialPillar returns a clear error when the
// CA file exists but contains no valid PEM certificate block (not a silent
// empty pool that produces an opaque TLS handshake failure).
func TestDialPillar_ErrorsOnBadCAFile(t *testing.T) {
	// Write a real self-signed keypair so LoadX509KeyPair succeeds; the bad part is the CA.
	certPEM, keyPEM := generateSelfSignedCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)
	badCAFile := writeTempFile(t, []byte("this is not a PEM certificate"))

	_, err := edge.DialPillar("localhost:9999", certFile, keyFile, badCAFile)
	if err == nil {
		t.Fatal("DialPillar should return error for CA file with no valid certs")
	}
	if !strings.Contains(err.Error(), "no certs parsed") {
		t.Errorf("error should mention 'no certs parsed', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeTempFile writes b to a temp file and returns the path.
func writeTempFile(t *testing.T, b []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "edge-test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

// generateSelfSignedCert generates a minimal self-signed cert+key pair for tests.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}
