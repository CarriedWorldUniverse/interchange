// Package gateway is the interchange-gateway: the single auth-aware reverse
// proxy that fronts the Carried World Builder (CWB) platform services
// (herald, cairn, ledger, commonplace). One public entry point; every request
// is routed by path-prefix to a backend, authenticated via herald (unless in
// bypass mode), and proxied with the *verified* identity injected as trusted
// X-CWB-* headers so the backend need not re-verify.
//
// See docs/2026-05-30-gateway-mvp-spec.md. The webhook push-relay is a
// separate (deferred) concern; this is the proxy only.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
)

// Identity is the verified caller, mirrored from heraldauth.Identity (kept as
// a local type so the gateway core is testable without the herald dep and so
// the adapter in cmd/ maps heraldauth.Identity → this).
type Identity struct {
	Subject          string
	Kind             string
	Org              string
	ResponsibleHuman string
	Scopes           []string
}

// Verifier verifies a bearer token and returns the caller identity. The
// production impl wraps heraldauth.Verifier (adapter in cmd/interchange-gateway).
type Verifier interface {
	Verify(ctx context.Context, token string) (Identity, error)
}

// Config configures a gateway.
type Config struct {
	// Verifier authenticates bearer tokens. Required unless AuthBypass.
	Verifier Verifier
	// AuthBypass skips authentication entirely (mode-1 / standalone posture).
	AuthBypass bool
	// Routes maps a path prefix → backend base URL, e.g.
	//   "/ledger" -> "http://ledger:8080"
	// The matched prefix is stripped before proxying. Longest prefix wins.
	Routes map[string]string
	// PublicPaths lists gateway-side request paths that skip bearer-token
	// verification. Entries ending in "/" match any path under that prefix
	// (e.g. "/herald/.well-known/" matches "/herald/.well-known/openid-
	// configuration"); other entries match exactly. Routing, anti-spoof
	// header stripping, and prefix stripping all still apply — only auth
	// is skipped. Use this to expose discovery endpoints (OIDC JWKS,
	// /.well-known/openid-configuration) that consumers need before they
	// can mint a token.
	PublicPaths []string
}

// Gateway is the configured proxy.
type Gateway struct {
	bypass   bool
	verify   Verifier
	routes   []route // sorted longest-prefix-first
	publicEx map[string]struct{}
	publicPx []string // entries that ended with "/"
}

type route struct {
	prefix  string
	backend *url.URL
	proxy   *httputil.ReverseProxy
}

// trustedHeaders are stripped from every inbound request before the gateway
// injects its own verified values — a client must never be able to forge them.
var trustedHeaders = []string{
	"X-CWB-Org", "X-CWB-Subject", "X-CWB-Kind", "X-CWB-Scopes", "X-CWB-Responsible-Human",
}

// New builds a Gateway. Errors on an unparseable backend URL, or a nil
// Verifier when auth is not bypassed.
func New(cfg Config) (*Gateway, error) {
	if !cfg.AuthBypass && cfg.Verifier == nil {
		return nil, errors.New("gateway: Verifier required when AuthBypass is false")
	}
	g := &Gateway{
		bypass:   cfg.AuthBypass,
		verify:   cfg.Verifier,
		publicEx: map[string]struct{}{},
	}
	for _, p := range cfg.PublicPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "/") {
			g.publicPx = append(g.publicPx, p)
		} else {
			g.publicEx[p] = struct{}{}
		}
	}
	for prefix, backend := range cfg.Routes {
		u, err := url.Parse(backend)
		if err != nil {
			return nil, fmt.Errorf("gateway: route %q backend %q: %w", prefix, backend, err)
		}
		g.routes = append(g.routes, route{
			prefix:  strings.TrimRight(prefix, "/"),
			backend: u,
			proxy:   httputil.NewSingleHostReverseProxy(u),
		})
	}
	// Longest prefix first so the most specific route wins.
	sort.Slice(g.routes, func(i, j int) bool {
		return len(g.routes[i].prefix) > len(g.routes[j].prefix)
	})
	return g, nil
}

// Handler returns the gateway's http.Handler.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"interchange-gateway"}`))
	})
	mux.HandleFunc("/", g.serve)
	return mux
}

func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	rt, rest, ok := g.match(r.URL.Path)
	if !ok {
		http.Error(w, `{"error":"no route"}`, http.StatusNotFound)
		return
	}

	// Anti-spoof: strip any client-supplied trusted headers before we (maybe)
	// inject verified ones. Done in ALL modes — even bypass must not let a
	// client assert identity headers.
	for _, h := range trustedHeaders {
		r.Header.Del(h)
	}

	if !g.bypass && !g.isPublic(r.URL.Path) {
		tok := bearer(r)
		if tok == "" {
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}
		id, err := g.verify.Verify(r.Context(), tok)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		injectIdentity(r, id)
	}

	// Rewrite the path: strip the matched prefix before proxying.
	r.URL.Path = rest
	rt.proxy.ServeHTTP(w, r)
}

// isPublic reports whether path is configured to skip auth. Exact matches
// take priority; otherwise any entry ending in "/" matches as a prefix.
func (g *Gateway) isPublic(path string) bool {
	if _, ok := g.publicEx[path]; ok {
		return true
	}
	for _, p := range g.publicPx {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// match finds the longest-prefix route for path and returns it plus the
// remainder (path with the prefix stripped, always leading-slashed).
func (g *Gateway) match(path string) (route, string, bool) {
	for _, rt := range g.routes {
		if path == rt.prefix || strings.HasPrefix(path, rt.prefix+"/") {
			rest := strings.TrimPrefix(path, rt.prefix)
			if rest == "" {
				rest = "/"
			}
			return rt, rest, true
		}
	}
	return route{}, "", false
}

func injectIdentity(r *http.Request, id Identity) {
	r.Header.Set("X-CWB-Org", id.Org)
	r.Header.Set("X-CWB-Subject", id.Subject)
	r.Header.Set("X-CWB-Kind", id.Kind)
	r.Header.Set("X-CWB-Scopes", strings.Join(id.Scopes, " "))
	if id.ResponsibleHuman != "" {
		r.Header.Set("X-CWB-Responsible-Human", id.ResponsibleHuman)
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return h[len(p):]
	}
	return ""
}
