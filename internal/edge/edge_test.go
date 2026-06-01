package edge_test

import (
	"context"
	"testing"

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
