package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	cairnv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/cairn/v1"
	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
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

// ---------------------------------------------------------------------------
// Ledger routing regression tests (Step 1 — test-first for Phase 2)
// ---------------------------------------------------------------------------

// stubIssueServiceSrv is a minimal IssueServiceServer that records which RPC
// was last invoked. Used to assert literal-path routes (/search, /my) beat
// the {key} wildcard in GetIssue.
type stubIssueServiceSrv struct {
	cwbv1.UnimplementedIssueServiceServer
	lastMethod string
}

func (s *stubIssueServiceSrv) GetIssue(_ context.Context, req *cwbv1.GetIssueRequest) (*cwbv1.GetIssueResponse, error) {
	s.lastMethod = "GetIssue"
	return &cwbv1.GetIssueResponse{}, nil
}

func (s *stubIssueServiceSrv) SearchIssues(_ context.Context, _ *cwbv1.SearchIssuesRequest) (*cwbv1.SearchIssuesResponse, error) {
	s.lastMethod = "SearchIssues"
	return &cwbv1.SearchIssuesResponse{}, nil
}

func (s *stubIssueServiceSrv) ListMyIssues(_ context.Context, _ *cwbv1.ListMyIssuesRequest) (*cwbv1.ListMyIssuesResponse, error) {
	s.lastMethod = "ListMyIssues"
	return &cwbv1.ListMyIssuesResponse{}, nil
}

// buildLedgerHandler constructs a ledger handler stack identical to the
// production wiring but using an in-process insecure gRPC server. All four
// ledger service handlers are registered on a shared ServeMux to match prod.
func buildLedgerHandler(t *testing.T, stub *stubIssueServiceSrv, v gateway.Verifier) http.Handler {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	cwbv1.RegisterIssueServiceServer(grpcSrv, stub)
	// ProjectService, OrgService, AdminService use their unimplemented stubs —
	// we only need IssueService to respond for these routing tests.
	cwbv1.RegisterProjectServiceServer(grpcSrv, &cwbv1.UnimplementedProjectServiceServer{})
	cwbv1.RegisterOrgServiceServer(grpcSrv, &cwbv1.UnimplementedOrgServiceServer{})
	cwbv1.RegisterAdminServiceServer(grpcSrv, &cwbv1.UnimplementedAdminServiceServer{})
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial stub: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ledgerMux := newGRPCMux()
	for _, reg := range []func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error{
		cwbv1.RegisterIssueServiceHandler,
		cwbv1.RegisterProjectServiceHandler,
		cwbv1.RegisterOrgServiceHandler,
		cwbv1.RegisterAdminServiceHandler,
	} {
		if err := reg(context.Background(), ledgerMux, conn); err != nil {
			t.Fatalf("register ledger handler: %v", err)
		}
	}

	return authInject(ledgerMux, v, "ledger")
}

// validLedgerIdentity returns a stubVerifier whose identity has the "ledger" product.
func validLedgerIdentity() stubVerifier {
	return stubVerifier{id: gateway.Identity{
		Subject:  "agent-ledger-test",
		Kind:     "agent",
		Org:      "org-ledger-test",
		Scopes:   []string{"issues:read"},
		Products: []string{"ledger"},
	}}
}

// TestLedgerHandler_SearchNotShadowedByGet is the key routing regression guard:
// POST /api/issues/search must dispatch to SearchIssues, NOT to GetIssue with
// key="search". This is the literal-vs-{key} collision that bit /knowledge.
func TestLedgerHandler_SearchNotShadowedByGet(t *testing.T) {
	stub := &stubIssueServiceSrv{}
	h := buildLedgerHandler(t, stub, validLedgerIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/issues/search", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/issues/search status = %d, body = %s", resp.StatusCode, b)
	}
	if stub.lastMethod != "SearchIssues" {
		t.Errorf("stub.lastMethod = %q, want \"SearchIssues\" (literal /search must beat {key} wildcard)", stub.lastMethod)
	}
}

// TestLedgerHandler_ListMyIssues verifies that GET /api/issues/my routes to
// ListMyIssues, not GetIssue(key="my").
func TestLedgerHandler_ListMyIssues(t *testing.T) {
	stub := &stubIssueServiceSrv{}
	h := buildLedgerHandler(t, stub, validLedgerIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/issues/my", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/issues/my status = %d, body = %s", resp.StatusCode, b)
	}
	if stub.lastMethod != "ListMyIssues" {
		t.Errorf("stub.lastMethod = %q, want \"ListMyIssues\"", stub.lastMethod)
	}
}

// TestLedgerHandler_NoToken401 verifies missing bearer token → 401 on the ledger edge.
func TestLedgerHandler_NoToken401(t *testing.T) {
	stub := &stubIssueServiceSrv{}
	h := buildLedgerHandler(t, stub, validLedgerIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/issues/search", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}
}

// TestLedgerHandler_MissingProduct403 verifies token without "ledger" product → 403.
func TestLedgerHandler_MissingProduct403(t *testing.T) {
	stub := &stubIssueServiceSrv{}
	v := stubVerifier{id: gateway.Identity{
		Subject:  "agent-x",
		Org:      "org-y",
		Products: []string{"cairn", "commonplace"}, // no "ledger"
	}}
	h := buildLedgerHandler(t, stub, v)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/issues/search", strings.NewReader(`{}`))
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

// ---------------------------------------------------------------------------
// Cairn composite-edge tests (Phase 3, step 3): one handler, two lanes —
// /api/... → cairn gRPC; .git → reverse-proxy to cairn HTTP.
// ---------------------------------------------------------------------------

// stubCairnRepoSrv records the incoming gRPC metadata + method for the API lane.
type stubCairnRepoSrv struct {
	cairnv1.UnimplementedRepoServiceServer
	lastMD     metadata.MD
	lastMethod string
}

func (s *stubCairnRepoSrv) CreateRepo(ctx context.Context, req *cairnv1.CreateRepoRequest) (*cairnv1.CreateRepoResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.lastMD = md
	s.lastMethod = "CreateRepo"
	return &cairnv1.CreateRepoResponse{Repo: &cairnv1.Repo{Id: "r1", Org: req.GetOrg(), Slug: req.GetSlug(), DefaultBranch: "main"}}, nil
}

// gitRec records the last request the stub git backend received.
type gitRec struct {
	path string
	hdr  http.Header
}

func newGitBackend(t *testing.T, rec *gitRec) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.path = r.URL.Path
		rec.hdr = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func buildCairnHandler(t *testing.T, repoStub cairnv1.RepoServiceServer, gitBackend string, v gateway.Verifier) http.Handler {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	cairnv1.RegisterRepoServiceServer(grpcSrv, repoStub)
	cairnv1.RegisterPullServiceServer(grpcSrv, &cairnv1.UnimplementedPullServiceServer{})
	cairnv1.RegisterOrgServiceServer(grpcSrv, &cairnv1.UnimplementedOrgServiceServer{})
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial stub: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	cairnMux := newGRPCMux()
	for _, reg := range []func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error{
		cairnv1.RegisterRepoServiceHandler,
		cairnv1.RegisterPullServiceHandler,
		cairnv1.RegisterOrgServiceHandler,
	} {
		if err := reg(context.Background(), cairnMux, conn); err != nil {
			t.Fatalf("register cairn handler: %v", err)
		}
	}
	gitURL, err := url.Parse(gitBackend)
	if err != nil {
		t.Fatalf("git backend url: %v", err)
	}
	return cairnComposite(cairnMux, httputil.NewSingleHostReverseProxy(gitURL), v, "cairn")
}

func validCairnIdentity() stubVerifier {
	return stubVerifier{id: gateway.Identity{
		Subject:  "agent-cairn",
		Kind:     "agent",
		Org:      "org-cairn",
		Scopes:   []string{"repo:read", "repo:write"},
		Products: []string{"cairn"},
	}}
}

// TestCairnComposite_APILaneToGRPC: /api/... reaches the cairn gRPC server with
// the verified identity as cwb-* metadata.
func TestCairnComposite_APILaneToGRPC(t *testing.T) {
	repoStub := &stubCairnRepoSrv{}
	git := newGitBackend(t, &gitRec{})
	h := buildCairnHandler(t, repoStub, git.URL, validCairnIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/orgs/org-cairn/repos", strings.NewReader(`{"slug":"widgets"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("API lane status = %d, body = %s", resp.StatusCode, b)
	}
	if repoStub.lastMethod != "CreateRepo" {
		t.Errorf("lastMethod = %q, want CreateRepo", repoStub.lastMethod)
	}
	if got := repoStub.lastMD.Get("cwb-org"); len(got) != 1 || got[0] != "org-cairn" {
		t.Errorf("cwb-org metadata = %v, want [org-cairn]", got)
	}
	if got := repoStub.lastMD.Get("cwb-subject"); len(got) != 1 || got[0] != "agent-cairn" {
		t.Errorf("cwb-subject metadata = %v, want [agent-cairn]", got)
	}
}

// TestCairnComposite_GitLaneToReverseProxy: a .git path reaches the HTTP git
// backend with the verified X-CWB-* headers injected.
func TestCairnComposite_GitLaneToReverseProxy(t *testing.T) {
	rec := &gitRec{}
	git := newGitBackend(t, rec)
	h := buildCairnHandler(t, &stubCairnRepoSrv{}, git.URL, validCairnIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/org-cairn/widgets.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("git lane status = %d", resp.StatusCode)
	}
	if rec.path != "/org-cairn/widgets.git/info/refs" {
		t.Errorf("git backend path = %q, want /org-cairn/widgets.git/info/refs", rec.path)
	}
	if rec.hdr.Get("X-CWB-Subject") != "agent-cairn" || rec.hdr.Get("X-CWB-Org") != "org-cairn" {
		t.Errorf("git backend X-CWB-* = subj %q org %q, want agent-cairn/org-cairn",
			rec.hdr.Get("X-CWB-Subject"), rec.hdr.Get("X-CWB-Org"))
	}
	if rec.hdr.Get("X-CWB-Scopes") != "repo:read repo:write" {
		t.Errorf("git backend X-CWB-Scopes = %q", rec.hdr.Get("X-CWB-Scopes"))
	}
}

// TestCairnComposite_NoToken401: both lanes require a bearer token.
func TestCairnComposite_NoToken401(t *testing.T) {
	git := newGitBackend(t, &gitRec{})
	h := buildCairnHandler(t, &stubCairnRepoSrv{}, git.URL, validCairnIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()
	for _, path := range []string{"/api/orgs/org-cairn/repos", "/org-cairn/widgets.git/info/refs"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s no-token status = %d, want 401", path, resp.StatusCode)
		}
	}
}

// TestCairnComposite_MissingProduct403: a token without the cairn product is 403.
func TestCairnComposite_MissingProduct403(t *testing.T) {
	git := newGitBackend(t, &gitRec{})
	v := stubVerifier{id: gateway.Identity{Subject: "a", Org: "o", Products: []string{"ledger"}}}
	h := buildCairnHandler(t, &stubCairnRepoSrv{}, git.URL, v)
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/api/orgs/o/repos", strings.NewReader(`{"slug":"x"}`))
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing-product status = %d, want 403", resp.StatusCode)
	}
}

// TestCairnComposite_SpoofStripped: client-forged identity headers are stripped
// on BOTH lanes — the backends see only the verified identity.
func TestCairnComposite_SpoofStripped(t *testing.T) {
	// git lane: a forged X-CWB-Subject must not reach the backend.
	rec := &gitRec{}
	git := newGitBackend(t, rec)
	h := buildCairnHandler(t, &stubCairnRepoSrv{}, git.URL, validCairnIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/org-cairn/widgets.git/info/refs", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("X-CWB-Subject", "evil")
	req.Header.Set("X-CWB-Org", "evil-org")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if rec.hdr.Get("X-CWB-Subject") != "agent-cairn" || rec.hdr.Get("X-CWB-Org") != "org-cairn" {
		t.Errorf("spoof leaked to git backend: subj %q org %q", rec.hdr.Get("X-CWB-Subject"), rec.hdr.Get("X-CWB-Org"))
	}

	// API lane: a forged Grpc-Metadata-cwb-org must not reach the gRPC server.
	repoStub := &stubCairnRepoSrv{}
	h2 := buildCairnHandler(t, repoStub, git.URL, validCairnIdentity())
	srv2 := httptest.NewServer(h2)
	defer srv2.Close()
	req2, _ := http.NewRequest("POST", srv2.URL+"/api/orgs/org-cairn/repos", strings.NewReader(`{"slug":"w"}`))
	req2.Header.Set("Authorization", "Bearer valid-token")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Grpc-Metadata-cwb-org", "evil-org")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if got := repoStub.lastMD.Get("cwb-org"); len(got) != 1 || got[0] != "org-cairn" {
		t.Errorf("spoof leaked to gRPC: cwb-org = %v, want [org-cairn]", got)
	}
}

// ---------------------------------------------------------------------------
// Herald composite-edge tests (Phase 4): OIDC/bootstrap → HTTP passthrough
// (unauthenticated); /api/orgs* + /api/humans/* → gRPC AdminService (JWT-authed).
// ---------------------------------------------------------------------------

type stubHeraldAdminSrv struct {
	heraldv1.UnimplementedAdminServiceServer
	lastMD     metadata.MD
	lastMethod string
}

func (s *stubHeraldAdminSrv) CreateOrg(ctx context.Context, r *heraldv1.CreateOrgRequest) (*heraldv1.CreateOrgResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.lastMD = md
	s.lastMethod = "CreateOrg"
	return &heraldv1.CreateOrgResponse{Org: &heraldv1.Org{Id: "org-1", Name: r.GetName()}}, nil
}

type heraldRec struct {
	path    string
	hadAuth bool
}

func newHeraldBackend(t *testing.T, rec *heraldRec) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.path = r.URL.Path
		rec.hadAuth = r.Header.Get("Authorization") != ""
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func buildHeraldHandler(t *testing.T, adminStub heraldv1.AdminServiceServer, httpBackend string, v gateway.Verifier) http.Handler {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	heraldv1.RegisterAdminServiceServer(grpcSrv, adminStub)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.GracefulStop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial stub: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	heraldMux := newGRPCMux()
	if err := heraldv1.RegisterAdminServiceHandler(context.Background(), heraldMux, conn); err != nil {
		t.Fatalf("register herald admin handler: %v", err)
	}
	u, err := url.Parse(httpBackend)
	if err != nil {
		t.Fatalf("backend url: %v", err)
	}
	return heraldComposite(heraldMux, httputil.NewSingleHostReverseProxy(u), v)
}

func validHeraldIdentity() stubVerifier {
	return stubVerifier{id: gateway.Identity{Subject: "owner", Kind: "human", Org: "cwb-admin", Scopes: []string{"herald:platform-admin"}}}
}

// TestHeraldComposite_OIDCPassthrough: OIDC paths reach herald's HTTP backend
// with NO gateway auth (tokenless).
func TestHeraldComposite_OIDCPassthrough(t *testing.T) {
	rec := &heraldRec{}
	backend := newHeraldBackend(t, rec)
	h := buildHeraldHandler(t, &stubHeraldAdminSrv{}, backend.URL, validHeraldIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, p := range []string{"/.well-known/openid-configuration", "/jwks", "/token"} {
		resp, err := http.Get(srv.URL + p) // no Authorization
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s tokenless status = %d, want 200", p, resp.StatusCode)
		}
	}
	if rec.path != "/token" {
		t.Errorf("backend last path = %q, want /token", rec.path)
	}
}

// TestHeraldComposite_RevokeTokenless: POST /revoke (RFC 7009 refresh-token
// revocation — credential is the refresh token in the body, NOT a bearer)
// reaches herald's HTTP backend with NO gateway auth, exactly like /token. It is
// one of the OIDC bootstrap routes, the ONLY tokenless paths through interchange.
// A non-bootstrap admin route still 401s without a bearer (covered by
// TestHeraldComposite_AdminNoToken401, asserted here too for contrast).
func TestHeraldComposite_RevokeTokenless(t *testing.T) {
	rec := &heraldRec{}
	backend := newHeraldBackend(t, rec)
	h := buildHeraldHandler(t, &stubHeraldAdminSrv{}, backend.URL, validHeraldIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	// /revoke with NO Authorization must reach herald (not 401'd by the gateway).
	resp, err := http.Post(srv.URL+"/revoke", "application/x-www-form-urlencoded",
		strings.NewReader("token=some-refresh-token"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/revoke tokenless status = %d, want 200 (must reach herald)", resp.StatusCode)
	}
	if rec.path != "/revoke" {
		t.Errorf("backend last path = %q, want /revoke", rec.path)
	}
	if rec.hadAuth {
		t.Errorf("/revoke passthrough must not carry an Authorization header")
	}

	// Contrast: a non-bootstrap admin route is still 401'd without a bearer.
	resp2, err := http.Post(srv.URL+"/api/orgs", "application/json", strings.NewReader(`{"name":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/orgs no-token status = %d, want 401", resp2.StatusCode)
	}
}

// TestHeraldComposite_AdminToGRPC: /api/orgs reaches the gRPC AdminService with
// the verified identity as cwb-* metadata.
func TestHeraldComposite_AdminToGRPC(t *testing.T) {
	adminStub := &stubHeraldAdminSrv{}
	backend := newHeraldBackend(t, &heraldRec{})
	h := buildHeraldHandler(t, adminStub, backend.URL, validHeraldIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/orgs", strings.NewReader(`{"name":"acme"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin status = %d, body=%s", resp.StatusCode, b)
	}
	if adminStub.lastMethod != "CreateOrg" {
		t.Errorf("lastMethod = %q, want CreateOrg", adminStub.lastMethod)
	}
	if got := adminStub.lastMD.Get("cwb-subject"); len(got) != 1 || got[0] != "owner" {
		t.Errorf("cwb-subject = %v, want [owner]", got)
	}
}

// TestHeraldComposite_AdminNoToken401: the admin lane requires a bearer token.
func TestHeraldComposite_AdminNoToken401(t *testing.T) {
	h := buildHeraldHandler(t, &stubHeraldAdminSrv{}, newHeraldBackend(t, &heraldRec{}).URL, validHeraldIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/api/orgs", "application/json", strings.NewReader(`{"name":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin no-token status = %d, want 401", resp.StatusCode)
	}
}

// TestHeraldComposite_SelfProvisionPassthrough: /api/agents (self-provision) is
// NOT the admin gRPC lane — it passes through to herald's HTTP backend, which
// self-authenticates the casket assertion (the gateway does not gate it).
func TestHeraldComposite_SelfProvisionPassthrough(t *testing.T) {
	rec := &heraldRec{}
	backend := newHeraldBackend(t, rec)
	h := buildHeraldHandler(t, &stubHeraldAdminSrv{}, backend.URL, validHeraldIdentity())
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/agents", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer casket-assertion") // herald verifies this, not the gateway
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("self-provision status = %d, want 200 (passthrough)", resp.StatusCode)
	}
	if rec.path != "/api/agents" || !rec.hadAuth {
		t.Errorf("backend got path=%q hadAuth=%v, want /api/agents + Authorization forwarded", rec.path, rec.hadAuth)
	}
}
