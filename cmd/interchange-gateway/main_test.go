package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/CarriedWorldUniverse/interchange/internal/edge"
	"github.com/CarriedWorldUniverse/interchange/internal/gateway"
)

// ---------------------------------------------------------------------------
// Stub KnowledgeServiceServer — captures incoming gRPC metadata.
// ---------------------------------------------------------------------------

type stubKnowledgeSrv struct {
	cwbv1.UnimplementedKnowledgeServiceServer
	lastMD     metadata.MD
	lastMethod string // records which RPC was last invoked
}

func (s *stubKnowledgeSrv) Store(ctx context.Context, req *cwbv1.StoreRequest) (*cwbv1.StoreResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.lastMD = md
	s.lastMethod = "Store"
	return &cwbv1.StoreResponse{
		Entry: &cwbv1.Entry{
			Id:      "entry-1",
			Topic:   req.GetTopic(),
			Content: req.GetContent(),
		},
	}, nil
}

func (s *stubKnowledgeSrv) Search(ctx context.Context, req *cwbv1.SearchRequest) (*cwbv1.SearchResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.lastMD = md
	s.lastMethod = "Search"
	return &cwbv1.SearchResponse{Hits: []*cwbv1.Hit{}}, nil
}

func (s *stubKnowledgeSrv) Get(ctx context.Context, req *cwbv1.GetRequest) (*cwbv1.GetResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.lastMD = md
	s.lastMethod = "Get"
	return &cwbv1.GetResponse{Entry: &cwbv1.Entry{Id: req.GetId()}}, nil
}

// ---------------------------------------------------------------------------
// stubVerifier adapts a fixed gateway.Identity to the heraldVerifier interface.
// ---------------------------------------------------------------------------

type stubVerifier struct {
	id  gateway.Identity
	err error
}

func (s stubVerifier) Verify(_ context.Context, _ string) (gateway.Identity, error) {
	return s.id, s.err
}

// ---------------------------------------------------------------------------
// buildKnowledgeHandler constructs the same handler stack as main() but using
// an in-process insecure gRPC server for test isolation.
// ---------------------------------------------------------------------------

func buildKnowledgeHandler(t *testing.T, stub *stubKnowledgeSrv, v gateway.Verifier) http.Handler {
	t.Helper()

	// Start in-process gRPC server (insecure for tests).
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	cwbv1.RegisterKnowledgeServiceServer(grpcSrv, stub)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.GracefulStop)

	// Dial the stub insecurely.
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial stub: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// Build gwMux with WithMetadata annotator that reads the stashed identity.
	gwMux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.HTTPBodyMarshaler{
			Marshaler: &runtime.JSONPb{
				MarshalOptions:   protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true},
				UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: true},
			},
		}),
		runtime.WithMetadata(func(ctx context.Context, _ *http.Request) metadata.MD {
			if id, ok := ctx.Value(identityCtxKey{}).(edge.Identity); ok {
				// Build metadata from the stashed verified identity.
				md := metadata.MD{}
				md.Set("cwb-org", id.Org)
				md.Set("cwb-subject", id.Subject)
				md.Set("cwb-kind", id.Kind)
				if len(id.Scopes) > 0 {
					md.Set("cwb-scopes", strings.Join(id.Scopes, " "))
				}
				if len(id.Products) > 0 {
					md.Set("cwb-products", strings.Join(id.Products, " "))
				}
				if id.ResponsibleHuman != "" {
					md.Set("cwb-responsible-human", id.ResponsibleHuman)
				}
				return md
			}
			return nil
		}),
	)
	if err := cwbv1.RegisterKnowledgeServiceHandler(context.Background(), gwMux, conn); err != nil {
		t.Fatalf("RegisterKnowledgeServiceHandler: %v", err)
	}

	return authInject(gwMux, v, "commonplace")
}

// ---------------------------------------------------------------------------
// Translation test: auth + metadata + JSON rendering
// ---------------------------------------------------------------------------

// TestKnowledgeHandler_StoreProxiesWithMetadata is the key test proving:
//  1. A valid token with product "commonplace" reaches the stub gRPC server.
//  2. The stub receives the cwb-org / cwb-subject / cwb-scopes metadata.
//  3. The JSON response is the bare entry with snake_case keys.
func TestKnowledgeHandler_StoreProxiesWithMetadata(t *testing.T) {
	stub := &stubKnowledgeSrv{}
	id := gateway.Identity{
		Subject:  "agent-99",
		Kind:     "agent",
		Org:      "org-test",
		Scopes:   []string{"kb:read", "kb:write"},
		Products: []string{"commonplace"},
	}
	v := stubVerifier{id: id}

	h := buildKnowledgeHandler(t, stub, v)
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := `{"topic":"test-topic","content":"hello world"}`
	req, _ := http.NewRequest("POST", srv.URL+"/api/knowledge", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}

	// Assert stub received cwb-* metadata.
	for _, key := range []string{"cwb-org", "cwb-subject", "cwb-scopes"} {
		vals := stub.lastMD.Get(key)
		if len(vals) == 0 {
			t.Errorf("stub gRPC server did not receive metadata key %q", key)
		}
	}
	if got := stub.lastMD.Get("cwb-org"); len(got) == 0 || got[0] != "org-test" {
		t.Errorf("cwb-org = %v, want org-test", got)
	}
	if got := stub.lastMD.Get("cwb-subject"); len(got) == 0 || got[0] != "agent-99" {
		t.Errorf("cwb-subject = %v, want agent-99", got)
	}

	// Assert JSON response is the bare entry (response_body:"entry") with snake_case keys.
	respBody, _ := io.ReadAll(resp.Body)
	var entry map[string]interface{}
	if err := json.Unmarshal(respBody, &entry); err != nil {
		t.Fatalf("response body is not JSON: %s", respBody)
	}
	// snake_case "id" field must be present (from Entry.id).
	if _, ok := entry["id"]; !ok {
		t.Errorf("response JSON missing 'id' key (want bare entry with snake_case keys): %s", respBody)
	}
}

// TestKnowledgeHandler_NoToken401 verifies missing bearer token → 401.
func TestKnowledgeHandler_NoToken401(t *testing.T) {
	stub := &stubKnowledgeSrv{}
	v := stubVerifier{id: gateway.Identity{Products: []string{"commonplace"}}}
	h := buildKnowledgeHandler(t, stub, v)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/knowledge", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}
}

// TestKnowledgeHandler_MissingProduct403 verifies token without "commonplace" product → 403.
func TestKnowledgeHandler_MissingProduct403(t *testing.T) {
	stub := &stubKnowledgeSrv{}
	// Products does NOT include "commonplace".
	v := stubVerifier{id: gateway.Identity{
		Subject:  "agent-x",
		Org:      "org-y",
		Products: []string{"cairn", "ledger"},
	}}
	h := buildKnowledgeHandler(t, stub, v)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/knowledge", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer some-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing-product status = %d, want 403", resp.StatusCode)
	}
}

// TestKnowledgeHandler_RejectsSpoofedIdentity proves that a client cannot forge
// cwb-* identity by supplying spoofed HTTP headers. The stub verifier returns
// a fixed verified identity (Org: "real-org"); even if the client sends
// Grpc-Metadata-cwb-org, Grpc-Metadata-Cwb-Org, and cwb-org all set to
// "evil-org", the gRPC server must see only "real-org" in cwb-org metadata —
// exactly one value and it must be the verified one.
func TestKnowledgeHandler_RejectsSpoofedIdentity(t *testing.T) {
	stub := &stubKnowledgeSrv{}
	id := gateway.Identity{
		Subject:  "real-subject",
		Kind:     "agent",
		Org:      "real-org",
		Products: []string{"commonplace"},
	}
	v := stubVerifier{id: id}

	h := buildKnowledgeHandler(t, stub, v)
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := `{"topic":"spoof-test","content":"hello"}`
	req, _ := http.NewRequest("POST", srv.URL+"/api/knowledge", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	// Attempt to spoof identity via all known vectors:
	req.Header.Set("Grpc-Metadata-cwb-org", "evil-org")       // lowercase variant
	req.Header.Set("Grpc-Metadata-Cwb-Org", "evil-org")       // canonical-case variant
	req.Header.Set("cwb-org", "evil-org")                     // raw cwb-* header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}

	// The gRPC stub MUST receive cwb-org == "real-org" (the verified value).
	got := stub.lastMD.Get("cwb-org")
	if len(got) != 1 {
		t.Fatalf("cwb-org metadata: got %d values %v, want exactly 1 (\"real-org\")", len(got), got)
	}
	if got[0] != "real-org" {
		t.Errorf("cwb-org = %q, want \"real-org\" (client spoof should have been stripped)", got[0])
	}

	// Also assert cwb-subject is the verified value, not spoofed.
	gotSubj := stub.lastMD.Get("cwb-subject")
	if len(gotSubj) != 1 || gotSubj[0] != "real-subject" {
		t.Errorf("cwb-subject = %v, want [\"real-subject\"]", gotSubj)
	}
}

func TestParseRoutes(t *testing.T) {
	got, err := parseRoutes("/herald=http://herald:8099, /ledger=http://ledger:8080 ,/cairn=http://cairn:3000")
	if err != nil {
		t.Fatalf("parseRoutes: %v", err)
	}
	want := map[string]string{
		"/herald": "http://herald:8099",
		"/ledger": "http://ledger:8080",
		"/cairn":  "http://cairn:3000",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d routes, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("route %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseRoutes_Empty(t *testing.T) {
	got, err := parseRoutes("")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty routes: got %v err %v", got, err)
	}
}

func TestParseRoutes_Bad(t *testing.T) {
	for _, bad := range []string{"noequals", "=nobackend", "/prefix="} {
		if _, err := parseRoutes(bad); err == nil {
			t.Errorf("parseRoutes(%q) should error", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Routing regression: GET /api/knowledge/search must route to Search, not Get.
// Before the fix, grpc-gateway matched the {id} wildcard first, routing
// GET /api/knowledge/search to Get(id="search") → NotFound → 404.
// ---------------------------------------------------------------------------

// validCommonplaceIdentity returns a stubVerifier whose identity has the
// "commonplace" product so it passes authInject.
func validCommonplaceIdentity() stubVerifier {
	return stubVerifier{id: gateway.Identity{
		Subject:  "agent-route-test",
		Kind:     "agent",
		Org:      "org-route-test",
		Scopes:   []string{"kb:read"},
		Products: []string{"commonplace"},
	}}
}

// TestKnowledgeHandler_SearchNotShadowedByGet proves that the literal path
// /api/knowledge/search routes to the Search RPC, not to Get(id="search").
// This is the definitive regression guard for the grpc-gateway route collision.
func TestKnowledgeHandler_SearchNotShadowedByGet(t *testing.T) {
	stub := &stubKnowledgeSrv{}
	h := buildKnowledgeHandler(t, stub, validCommonplaceIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/knowledge/search?q=hi&top_k=3", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/knowledge/search?q=hi&top_k=3 status = %d, body = %s", resp.StatusCode, b)
	}

	if stub.lastMethod != "Search" {
		t.Errorf("stub.lastMethod = %q, want \"Search\" (route collision: Get shadowed Search)", stub.lastMethod)
	}
}

// TestKnowledgeHandler_GetByIdNotHTTPRouted documents the intentional contract
// reduction: after dropping Get's HTTP binding, GET /api/knowledge/{id}
// (for any non-"search" id) returns 404 via the gateway.
func TestKnowledgeHandler_GetByIdNotHTTPRouted(t *testing.T) {
	stub := &stubKnowledgeSrv{}
	h := buildKnowledgeHandler(t, stub, validCommonplaceIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/knowledge/some-entry-id", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Get is gRPC-only; no HTTP binding → grpc-gateway returns 404 or 501
	// (Method Not Allowed) depending on whether other methods match the path
	// segment. Either is acceptable; what matters is it is NOT 200.
	if resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /api/knowledge/some-entry-id status = 200, want non-200 (Get is gRPC-only), body = %s", b)
	}
	// Also assert Get was NOT invoked (no HTTP route should reach it).
	if stub.lastMethod == "Get" {
		t.Error("stub.lastMethod = \"Get\": HTTP Get route should not exist (grpc-gateway binding was removed)")
	}
}
