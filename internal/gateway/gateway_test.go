package gateway_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/interchange/internal/gateway"
)

// fakeVerifier stands in for heraldauth.Verifier in tests.
type fakeVerifier struct {
	id  gateway.Identity
	err error
}

func (f fakeVerifier) Verify(_ context.Context, token string) (gateway.Identity, error) {
	if f.err != nil {
		return gateway.Identity{}, f.err
	}
	return f.id, nil
}

// echoBackend returns a handler that echoes the request path + selected headers,
// so tests can assert what the gateway forwarded.
func echoBackend(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("X-Echo-Org", r.Header.Get("X-CWB-Org"))
		w.Header().Set("X-Echo-Subject", r.Header.Get("X-CWB-Subject"))
		w.Header().Set("X-Echo-Scopes", r.Header.Get("X-CWB-Scopes"))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
}

func newGateway(t *testing.T, v gateway.Verifier, bypass bool, routes map[string]string) http.Handler {
	t.Helper()
	g, err := gateway.New(gateway.Config{
		Verifier:   v,
		AuthBypass: bypass,
		Routes:     routes,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	return g.Handler()
}

func TestRoute_AuthedRequestProxiesWithIdentityHeaders(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	v := fakeVerifier{id: gateway.Identity{
		Subject: "agent-1", Org: "org-a", Kind: "agent", Scopes: []string{"repo:read", "repo:write"},
	}}
	h := newGateway(t, v, false, map[string]string{"/ledger": backend.URL})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/ledger/api/issues", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	// Prefix stripped: backend saw /api/issues, not /ledger/api/issues.
	if got := resp.Header.Get("X-Echo-Path"); got != "/api/issues" {
		t.Errorf("backend path = %q, want /api/issues (prefix stripped)", got)
	}
	// Verified identity injected.
	if resp.Header.Get("X-Echo-Org") != "org-a" {
		t.Errorf("X-CWB-Org not injected: %q", resp.Header.Get("X-Echo-Org"))
	}
	if resp.Header.Get("X-Echo-Subject") != "agent-1" {
		t.Errorf("X-CWB-Subject not injected: %q", resp.Header.Get("X-Echo-Subject"))
	}
	if resp.Header.Get("X-Echo-Scopes") != "repo:read repo:write" {
		t.Errorf("X-CWB-Scopes = %q", resp.Header.Get("X-Echo-Scopes"))
	}
}

func TestRoute_NoTokenRejected401(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	h := newGateway(t, fakeVerifier{}, false, map[string]string{"/ledger": backend.URL})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ledger/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}
}

func TestRoute_InvalidTokenRejected401(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	v := fakeVerifier{err: io.EOF} // any verify error
	h := newGateway(t, v, false, map[string]string{"/ledger": backend.URL})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/ledger/x", nil)
	req.Header.Set("Authorization", "Bearer bad")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid-token status = %d, want 401", resp.StatusCode)
	}
}

func TestRoute_ClientSuppliedIdentityHeadersStripped(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	v := fakeVerifier{id: gateway.Identity{Subject: "real", Org: "real-org", Kind: "agent"}}
	h := newGateway(t, v, false, map[string]string{"/ledger": backend.URL})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/ledger/x", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	req.Header.Set("X-CWB-Org", "spoofed-org")     // client tries to forge
	req.Header.Set("X-CWB-Subject", "spoofed-sub") // client tries to forge
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Echo-Org") != "real-org" {
		t.Errorf("spoofed org leaked: backend saw %q (must be the verified value)", resp.Header.Get("X-Echo-Org"))
	}
	if resp.Header.Get("X-Echo-Subject") != "real" {
		t.Errorf("spoofed subject leaked: %q", resp.Header.Get("X-Echo-Subject"))
	}
}

func TestRoute_NoMatchReturns404(t *testing.T) {
	h := newGateway(t, fakeVerifier{}, false, map[string]string{"/ledger": "http://unused"})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/nope/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("no-route status = %d, want 404", resp.StatusCode)
	}
}

func TestBypass_SkipsAuthAndProxies(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	// bypass=true; no token at all should still proxy.
	h := newGateway(t, fakeVerifier{err: io.EOF}, true, map[string]string{"/ledger": backend.URL})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ledger/api/issues")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("bypass status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Echo-Path"); got != "/api/issues" {
		t.Errorf("bypass backend path = %q", got)
	}
}

func TestHealthz_NotProxied(t *testing.T) {
	h := newGateway(t, fakeVerifier{}, false, map[string]string{"/ledger": "http://unused"})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("healthz body = %q", body)
	}
}

func TestPublicPaths_ExactMatchBypassesAuth(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	g, err := gateway.New(gateway.Config{
		Verifier:    fakeVerifier{}, // would error if invoked
		AuthBypass:  false,
		Routes:      map[string]string{"/herald": backend.URL},
		PublicPaths: []string{"/herald/jwks"},
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	// Public path: no Authorization header, expect 200 + prefix-stripped path.
	resp, err := http.Get(srv.URL + "/herald/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("public path status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Echo-Path"); got != "/jwks" {
		t.Errorf("backend path = %q, want /jwks (prefix stripped)", got)
	}
	// No identity should be injected on a public hit.
	if got := resp.Header.Get("X-Echo-Org"); got != "" {
		t.Errorf("X-CWB-Org should be absent on public hit, got %q", got)
	}
}

func TestPublicPaths_PrefixMatchBypassesAuth(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	g, err := gateway.New(gateway.Config{
		Verifier:    fakeVerifier{},
		AuthBypass:  false,
		Routes:      map[string]string{"/herald": backend.URL},
		PublicPaths: []string{"/herald/.well-known/"}, // trailing / = prefix
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/herald/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("well-known status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Echo-Path"); got != "/.well-known/openid-configuration" {
		t.Errorf("backend path = %q", got)
	}
}

func TestPublicPaths_NonPublicStill401(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	g, err := gateway.New(gateway.Config{
		Verifier:    fakeVerifier{},
		AuthBypass:  false,
		Routes:      map[string]string{"/herald": backend.URL},
		PublicPaths: []string{"/herald/jwks"},
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/herald/api/orgs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-public path status = %d, want 401", resp.StatusCode)
	}
}

func TestPublicPaths_StillStripSpoofedHeaders(t *testing.T) {
	backend := echoBackend(t)
	defer backend.Close()
	g, err := gateway.New(gateway.Config{
		Verifier:    fakeVerifier{},
		AuthBypass:  false,
		Routes:      map[string]string{"/herald": backend.URL},
		PublicPaths: []string{"/herald/jwks"},
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/herald/jwks", nil)
	req.Header.Set("X-CWB-Org", "spoofed-org")
	req.Header.Set("X-CWB-Subject", "spoofed-sub")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Echo-Org"); got != "" {
		t.Errorf("spoofed org leaked through public path: %q", got)
	}
	if got := resp.Header.Get("X-Echo-Subject"); got != "" {
		t.Errorf("spoofed subject leaked through public path: %q", got)
	}
}

func TestPublicPaths_WithoutMatchingRouteStill404(t *testing.T) {
	g, err := gateway.New(gateway.Config{
		Verifier:    fakeVerifier{},
		AuthBypass:  false,
		Routes:      map[string]string{"/herald": "http://unused"},
		PublicPaths: []string{"/anywhere"},
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/anywhere")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("public-but-no-route status = %d, want 404", resp.StatusCode)
	}
}

func TestRoute_LongestPrefixWins(t *testing.T) {
	b1 := echoBackend(t)
	defer b1.Close()
	b2 := echoBackend(t)
	defer b2.Close()
	// /ledger and /ledger/special — the longer should win for /ledger/special/*.
	v := fakeVerifier{id: gateway.Identity{Subject: "s", Org: "o"}}
	h := newGateway(t, v, false, map[string]string{
		"/ledger":         b1.URL,
		"/ledger/special": b2.URL,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/ledger/special/x", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// b2 strips "/ledger/special" → backend sees "/x".
	if got := resp.Header.Get("X-Echo-Path"); got != "/x" {
		t.Errorf("longest-prefix path = %q, want /x (matched /ledger/special)", got)
	}
}
