// Command interchange-gateway is the single auth-aware reverse proxy fronting
// the Carried World Builder (CWB) platform services. It is SEPARATE from
// cmd/interchange (the E2E pair-relay) — two binaries, two concerns.
//
// It routes by path-prefix to backend services, authenticates callers via
// herald (verifying tokens locally against herald's JWKS through heraldauth),
// and proxies with the verified identity injected as trusted X-CWB-* headers.
// In bypass mode it skips auth (mode-1 / standalone).
//
// Config (env):
//
//	INTERCHANGE_ADDR                listen addr (default :8080)
//	INTERCHANGE_ROUTES              "prefix=backend,prefix=backend,..." e.g.
//	                                "/herald=http://herald:8099,/cairn=http://cairn:3000"
//	                                Note: /knowledge and /ledger are NOT listed here; they
//	                                are handled via grpc-gateway translation (see below).
//	INTERCHANGE_HERALD_ISSUER       herald issuer URL (required unless bypass) — for JWKS verify
//	INTERCHANGE_HERALD_JWKS_URL     optional override pointing heraldauth at an
//	                                internal JWKS endpoint instead of going through
//	                                discovery on the public issuer. Use this when
//	                                the gateway is fronting its own issuer to avoid
//	                                a boot loop calling itself, e.g.
//	                                  INTERCHANGE_HERALD_JWKS_URL=http://herald.cwb.svc:8099/jwks
//	INTERCHANGE_AUTH_BYPASS         "1" to skip auth (mode-1 standalone)
//	INTERCHANGE_PUBLIC_PATHS        "path,path,..." gateway-side paths that skip
//	                                bearer-token verification (routing + anti-spoof
//	                                still apply). Entries ending in "/" are prefix
//	                                matches, e.g.
//	                                  "/herald/.well-known/,/herald/jwks"
//	INTERCHANGE_COMMONPLACE_GRPC    commonplace gRPC address for grpc-gateway translation,
//	                                e.g. "commonplace.cwb.svc:50051"
//	INTERCHANGE_LEDGER_GRPC         ledger gRPC address for grpc-gateway translation,
//	                                e.g. "ledger.cwb.svc:50051"
//	INTERCHANGE_TLS_CERT            interchange's mTLS client certificate (PEM)
//	INTERCHANGE_TLS_KEY             interchange's mTLS client key (PEM)
//	INTERCHANGE_TLS_CA              CA certificate for verifying pillar server certs (PEM)
//	INTERCHANGE_SHUTDOWN_TIMEOUT    graceful-shutdown drain timeout on SIGTERM/SIGINT
//	                                (Go duration, default "25s"; keep under the k8s
//	                                terminationGracePeriod)
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	cairnv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/cairn/v1"
	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"github.com/CarriedWorldUniverse/herald/heraldauth"
	"github.com/CarriedWorldUniverse/interchange/internal/edge"
	"github.com/CarriedWorldUniverse/interchange/internal/gateway"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	addr := env("INTERCHANGE_ADDR", ":8080")
	bypass := os.Getenv("INTERCHANGE_AUTH_BYPASS") == "1"

	routes, err := parseRoutes(os.Getenv("INTERCHANGE_ROUTES"))
	if err != nil {
		log.Fatalf("interchange-gateway: routes: %v", err)
	}

	var verifier gateway.Verifier
	if bypass {
		log.Printf("interchange-gateway: WARNING AUTH BYPASS active — all requests proxied without authentication (mode-1/standalone)")
	} else {
		issuer := os.Getenv("INTERCHANGE_HERALD_ISSUER")
		if issuer == "" {
			log.Fatal("interchange-gateway: INTERCHANGE_HERALD_ISSUER required (or set INTERCHANGE_AUTH_BYPASS=1)")
		}
		hv, err := heraldauth.New(context.Background(), heraldauth.Config{
			Issuer:  issuer,
			JWKSURL: os.Getenv("INTERCHANGE_HERALD_JWKS_URL"),
		})
		if err != nil {
			log.Fatalf("interchange-gateway: herald verifier (issuer=%s): %v", issuer, err)
		}
		verifier = heraldVerifier{hv}
	}

	publicPaths := parsePublicPaths(os.Getenv("INTERCHANGE_PUBLIC_PATHS"))

	tlsCert := os.Getenv("INTERCHANGE_TLS_CERT")
	tlsKey := os.Getenv("INTERCHANGE_TLS_KEY")
	tlsCA := os.Getenv("INTERCHANGE_TLS_CA")

	// -----------------------------------------------------------------------
	// /knowledge → commonplace gRPC edge.
	// newGRPCMux() provides the shared ServeMux config (marshaler + identity
	// annotator) reused by all pillar gRPC edges.
	// -----------------------------------------------------------------------
	knowledgeMux := newGRPCMux()
	knowledgeAddr := os.Getenv("INTERCHANGE_COMMONPLACE_GRPC")
	if knowledgeAddr == "" {
		knowledgeAddr = "commonplace.cwb.svc:50051"
	}
	knowledgeConn, err := edge.DialPillar(knowledgeAddr, tlsCert, tlsKey, tlsCA)
	if err != nil {
		log.Fatalf("interchange-gateway: dial commonplace (%s): %v", knowledgeAddr, err)
	}
	if err := cwbv1.RegisterKnowledgeServiceHandler(context.Background(), knowledgeMux, knowledgeConn); err != nil {
		log.Fatalf("interchange-gateway: register knowledge handler: %v", err)
	}
	knowledgeHandler := authInject(knowledgeMux, verifier, "commonplace")

	// -----------------------------------------------------------------------
	// /ledger → ledger gRPC edge (Issue/Project/Org/Admin services).
	// -----------------------------------------------------------------------
	ledgerMux := newGRPCMux()
	ledgerAddr := os.Getenv("INTERCHANGE_LEDGER_GRPC")
	if ledgerAddr == "" {
		ledgerAddr = "ledger.cwb.svc:50051"
	}
	ledgerConn, err := edge.DialPillar(ledgerAddr, tlsCert, tlsKey, tlsCA)
	if err != nil {
		log.Fatalf("interchange-gateway: dial ledger (%s): %v", ledgerAddr, err)
	}
	for _, reg := range []func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error{
		cwbv1.RegisterIssueServiceHandler,
		cwbv1.RegisterProjectServiceHandler,
		cwbv1.RegisterOrgServiceHandler,
		cwbv1.RegisterAdminServiceHandler,
	} {
		if err := reg(context.Background(), ledgerMux, ledgerConn); err != nil {
			log.Fatalf("interchange-gateway: register ledger handler: %v", err)
		}
	}
	ledgerHandler := authInject(ledgerMux, verifier, "ledger")

	// -----------------------------------------------------------------------
	// /cairn → COMPOSITE edge. cairn is dual-transport: its JSON API is gRPC,
	// but git Smart-HTTP stays plain HTTP (git can't be gRPC). One handler
	// auths once, then path-splits: /api/... → grpc-gateway (mTLS to cairn's
	// gRPC), everything else (the .git Smart-HTTP paths) → reverse-proxy to
	// cairn's HTTP backend with X-CWB-* injected. The git backend URL is reused
	// from the existing /cairn reverse-proxy route, which we remove from the
	// plain Routes so /cairn is owned by the composite handler alone.
	// -----------------------------------------------------------------------
	cairnGRPC := os.Getenv("INTERCHANGE_CAIRN_GRPC")
	if cairnGRPC == "" {
		cairnGRPC = "cairn.cwb.svc:8102"
	}
	cairnHTTP := routes["/cairn"]
	if cairnHTTP == "" {
		cairnHTTP = "http://cairn.cwb.svc:8100"
	}
	delete(routes, "/cairn")
	cairnConn, err := edge.DialPillar(cairnGRPC, tlsCert, tlsKey, tlsCA)
	if err != nil {
		log.Fatalf("interchange-gateway: dial cairn (%s): %v", cairnGRPC, err)
	}
	cairnMux := newGRPCMux()
	for _, reg := range []func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error{
		cairnv1.RegisterRepoServiceHandler,
		cairnv1.RegisterPullServiceHandler,
		cairnv1.RegisterOrgServiceHandler,
	} {
		if err := reg(context.Background(), cairnMux, cairnConn); err != nil {
			log.Fatalf("interchange-gateway: register cairn handler: %v", err)
		}
	}
	cairnGitURL, err := url.Parse(cairnHTTP)
	if err != nil {
		log.Fatalf("interchange-gateway: cairn http backend %q: %v", cairnHTTP, err)
	}
	cairnHandler := cairnComposite(cairnMux, httputil.NewSingleHostReverseProxy(cairnGitURL), verifier, "cairn")

	// -----------------------------------------------------------------------
	// /herald → COMPOSITE edge (Phase 4). herald is dual-faced: OIDC
	// (discovery/JWKS/token) + the agent-bootstrap stay HTTP and are
	// herald-self-authed, so they pass through UNauthenticated; only the admin
	// paths (/api/orgs*, /api/humans/*) route to herald's gRPC AdminService,
	// JWT-authed with the verified identity injected as cwb-* metadata. herald
	// is core → no product gate. by-fingerprint is NOT exposed here (gRPC-only,
	// dialed directly by cairn). The herald HTTP backend is reused from the
	// existing /herald reverse-proxy route, removed from the plain Routes.
	// -----------------------------------------------------------------------
	heraldGRPC := os.Getenv("INTERCHANGE_HERALD_GRPC")
	if heraldGRPC == "" {
		heraldGRPC = "herald.cwb.svc:8098"
	}
	heraldHTTP := routes["/herald"]
	if heraldHTTP == "" {
		heraldHTTP = "http://herald.cwb.svc:8099"
	}
	delete(routes, "/herald")
	heraldConn, err := edge.DialPillar(heraldGRPC, tlsCert, tlsKey, tlsCA)
	if err != nil {
		log.Fatalf("interchange-gateway: dial herald (%s): %v", heraldGRPC, err)
	}
	heraldMux := newGRPCMux()
	if err := heraldv1.RegisterAdminServiceHandler(context.Background(), heraldMux, heraldConn); err != nil {
		log.Fatalf("interchange-gateway: register herald admin handler: %v", err)
	}
	heraldHTTPURL, err := url.Parse(heraldHTTP)
	if err != nil {
		log.Fatalf("interchange-gateway: herald http backend %q: %v", heraldHTTP, err)
	}
	heraldHandler := heraldComposite(heraldMux, httputil.NewSingleHostReverseProxy(heraldHTTPURL), verifier)

	if len(routes) == 0 && !bypass {
		log.Printf("interchange-gateway: WARNING no reverse-proxy routes configured (only grpc-gateway edges)")
	}

	g, err := gateway.New(gateway.Config{
		Verifier:      verifier,
		AuthBypass:    bypass,
		Routes:        routes,
		PublicPaths:   publicPaths,
		RouteProducts: routeProducts,
		GRPCHandlers: map[string]http.Handler{
			"/knowledge": knowledgeHandler,
			"/ledger":    ledgerHandler,
			"/cairn":     cairnHandler,
			"/herald":    heraldHandler,
		},
	})
	if err != nil {
		log.Fatalf("interchange-gateway: %v", err)
	}

	srv := &http.Server{Addr: addr, Handler: g.Handler()}

	// Graceful shutdown: on SIGTERM/SIGINT stop accepting new connections and
	// let in-flight requests drain, bounded by INTERCHANGE_SHUTDOWN_TIMEOUT
	// (default 25s — kept under k8s's default 30s terminationGracePeriod so
	// Shutdown completes before SIGKILL). A long git clone/push still streaming
	// at the deadline is cut, but ordinary requests finish cleanly and the pod
	// exits 0 — no more spurious "Error" status on terminating pods during a
	// rolling update (NEX-428 follow-up).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("interchange-gateway listening on %s (bypass=%v, routes=%d, public_paths=%d)", addr, bypass, len(routes), len(publicPaths))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Fatalf("interchange-gateway: %v", err)
	case <-ctx.Done():
		stop() // restore default handling so a second signal force-kills
		log.Printf("interchange-gateway: shutdown signal received, draining (timeout %s)…", shutdownTimeout())
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout())
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Fatalf("interchange-gateway: graceful shutdown failed: %v", err)
		}
		log.Printf("interchange-gateway: shutdown complete")
	}
}

// shutdownTimeout is how long graceful shutdown waits for in-flight requests
// to drain. Override with INTERCHANGE_SHUTDOWN_TIMEOUT (a Go duration, e.g.
// "25s"); default 25s, deliberately under the k8s 30s terminationGracePeriod.
func shutdownTimeout() time.Duration {
	if v := os.Getenv("INTERCHANGE_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 25 * time.Second
}

// identityCtxKey is the typed key used to stash the verified edge.Identity in
// the request context so the grpc-gateway WithMetadata annotator can read it.
type identityCtxKey struct{}

// newGRPCMux returns a runtime.ServeMux configured with the shared CWB options
// used by every gRPC pillar edge:
//   - JSONPb marshaler with snake_case keys and EmitUnpopulated fields.
//   - WithMetadata annotator that reads the verified edge.Identity stashed by
//     authInject (via identityCtxKey) and emits cwb-* gRPC metadata on the
//     outgoing call to the pillar. grpc-gateway merges this MD into the
//     outgoing context before dispatching, so the pillar's incoming metadata
//     will always carry the verified identity regardless of what the client sent.
func newGRPCMux() *runtime.ServeMux {
	return runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.HTTPBodyMarshaler{
			Marshaler: &runtime.JSONPb{
				MarshalOptions:   protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true},
				UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: true},
			},
		}),
		runtime.WithMetadata(func(ctx context.Context, _ *http.Request) metadata.MD {
			id, ok := ctx.Value(identityCtxKey{}).(edge.Identity)
			if !ok {
				return nil
			}
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
		}),
	)
}

// authInject returns an http.Handler that:
//  1. Extracts and verifies the bearer token via v.
//  2. Checks product entitlement (NEX-427) — 403 if the org doesn't have product.
//  3. Strips any client-supplied cwb-* headers (anti-spoof for the HTTP layer;
//     the grpc-gateway WithMetadata annotator handles the gRPC layer).
//  4. Stashes the verified identity in the request context via identityCtxKey
//     so the grpc-gateway WithMetadata annotator can emit cwb-* gRPC metadata.
//  5. Forwards to next (the grpc-gateway mux).
//
// The handler owns ALL auth for the /knowledge gRPC-mode route; the outer
// gateway skips its own bearer-verify for gRPC-mode routes.
func authInject(next http.Handler, v gateway.Verifier, product string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}
		// In bypass mode v may be nil; if so, skip verify and inject a zero identity.
		var gid gateway.Identity
		if v != nil {
			var err error
			gid, err = v.Verify(r.Context(), tok)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
		}
		id := edge.Identity{
			Subject:          gid.Subject,
			Kind:             gid.Kind,
			Org:              gid.Org,
			ResponsibleHuman: gid.ResponsibleHuman,
			Scopes:           gid.Scopes,
			Products:         gid.Products,
		}
		if !edge.HasProduct(id, product) {
			http.Error(w, `{"error":"product not enabled for org"}`, http.StatusForbidden)
			return
		}
		// Strip any client-supplied cwb-* HTTP headers (anti-spoof).
		for _, k := range []string{
			"cwb-org", "cwb-subject", "cwb-kind",
			"cwb-scopes", "cwb-products", "cwb-responsible-human",
		} {
			r.Header.Del(k)
			r.Header.Del("Grpc-Metadata-" + k)
		}
		// Stash verified identity in context for the WithMetadata annotator.
		ctx := context.WithValue(r.Context(), identityCtxKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// cairnComposite is the dual-transport /cairn edge. It authenticates the
// bearer token ONCE (and checks product entitlement), strips any client-forged
// identity headers, then dispatches by path:
//   - /api/... → the gRPC-gateway mux (apiMux). The verified identity is stashed
//     in context so the WithMetadata annotator emits cwb-* metadata to cairn's
//     gRPC server over mTLS.
//   - everything else (the .git Smart-HTTP paths) → the git reverse-proxy with
//     the verified X-CWB-* headers injected (cairn's HTTP git lane is
//     header-trust, like every reverse-proxied pillar).
//
// The outer gateway dispatches gRPC-mode routes WITHOUT its own bearer-verify /
// header-strip, so this handler owns auth + anti-spoof for BOTH lanes.
func cairnComposite(apiMux, gitProxy http.Handler, v gateway.Verifier, product string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}
		var gid gateway.Identity
		if v != nil {
			var err error
			gid, err = v.Verify(r.Context(), tok)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
		}
		id := edge.Identity{
			Subject:          gid.Subject,
			Kind:             gid.Kind,
			Org:              gid.Org,
			ResponsibleHuman: gid.ResponsibleHuman,
			Scopes:           gid.Scopes,
			Products:         gid.Products,
		}
		if !edge.HasProduct(id, product) {
			http.Error(w, `{"error":"product not enabled for org"}`, http.StatusForbidden)
			return
		}
		stripSpoofedIdentity(r)

		if strings.HasPrefix(r.URL.Path, "/api/") {
			// API lane → cairn gRPC (identity carried as gRPC metadata).
			ctx := context.WithValue(r.Context(), identityCtxKey{}, id)
			apiMux.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// git lane → cairn HTTP (identity carried as trusted X-CWB-* headers).
		injectCWBHeaders(r, id)
		gitProxy.ServeHTTP(w, r)
	})
}

// heraldComposite is the dual-faced /herald edge (Phase 4). herald's OIDC
// (discovery/JWKS/token/revoke) + agent-bootstrap (self-provision/validate) stay
// HTTP and are herald-self-authed, so they pass through UNauthenticated — /revoke
// (RFC 7009) is credentialed by the refresh token in the body, not a bearer, so
// like /token it must be tokenless; only the admin paths (/api/orgs*,
// /api/humans/*, /api/me) route to herald's gRPC AdminService,
// JWT-authed with the verified identity injected as cwb-* metadata. herald is a
// core product → no product-entitlement gate. by-fingerprint is not reachable
// here (gRPC-only, dialed directly by cairn over mTLS).
func heraldComposite(apiMux, httpProxy http.Handler, v gateway.Verifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/api/orgs") && !strings.HasPrefix(p, "/api/humans/") && p != "/api/me" {
			// OIDC bootstrap (discovery/jwks/token/revoke) + agent-bootstrap +
			// healthz → HTTP passthrough; herald self-auths. /revoke (RFC 7009)
			// is tokenless like /token — its credential is the refresh token in
			// the body. These OIDC bootstrap routes are the ONLY tokenless paths.
			// Strip any client-forged identity (defence in depth — herald does
			// not trust injected identity on this lane).
			stripSpoofedIdentity(r)
			httpProxy.ServeHTTP(w, r)
			return
		}
		// Admin gRPC lane: verify the herald JWT, inject cwb-* identity.
		tok := bearer(r)
		if tok == "" {
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}
		var gid gateway.Identity
		if v != nil {
			var err error
			gid, err = v.Verify(r.Context(), tok)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
		}
		id := edge.Identity{
			Subject:          gid.Subject,
			Kind:             gid.Kind,
			Org:              gid.Org,
			ResponsibleHuman: gid.ResponsibleHuman,
			Scopes:           gid.Scopes,
			Products:         gid.Products,
		}
		stripSpoofedIdentity(r)
		ctx := context.WithValue(r.Context(), identityCtxKey{}, id)
		apiMux.ServeHTTP(w, r.WithContext(ctx))
	})
}

// stripSpoofedIdentity removes any client-supplied identity headers — both the
// gRPC-style cwb-*/Grpc-Metadata-cwb-* (API lane) and the X-CWB-* HTTP headers
// (git lane) — so neither lane can be spoofed before the gateway injects the
// verified values.
func stripSpoofedIdentity(r *http.Request) {
	for _, k := range []string{"cwb-org", "cwb-subject", "cwb-kind", "cwb-scopes", "cwb-products", "cwb-responsible-human"} {
		r.Header.Del(k)
		r.Header.Del("Grpc-Metadata-" + k)
	}
	for _, k := range []string{"X-CWB-Org", "X-CWB-Subject", "X-CWB-Kind", "X-CWB-Scopes", "X-CWB-Products", "X-CWB-Responsible-Human"} {
		r.Header.Del(k)
	}
}

// injectCWBHeaders sets the verified identity as X-CWB-* headers for the git
// reverse-proxy lane (cairn's handleGit reads these).
func injectCWBHeaders(r *http.Request, id edge.Identity) {
	r.Header.Set("X-CWB-Org", id.Org)
	r.Header.Set("X-CWB-Subject", id.Subject)
	r.Header.Set("X-CWB-Kind", id.Kind)
	r.Header.Set("X-CWB-Scopes", strings.Join(id.Scopes, " "))
	r.Header.Set("X-CWB-Products", strings.Join(id.Products, " "))
	if id.ResponsibleHuman != "" {
		r.Header.Set("X-CWB-Responsible-Human", id.ResponsibleHuman)
	}
}

// bearer extracts the token from "Authorization: Bearer <token>".
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return h[len(p):]
	}
	return ""
}

// heraldVerifier adapts *heraldauth.Verifier to gateway.Verifier.
type heraldVerifier struct{ v *heraldauth.Verifier }

func (h heraldVerifier) Verify(ctx context.Context, token string) (gateway.Identity, error) {
	id, err := h.v.Verify(ctx, token)
	if err != nil {
		return gateway.Identity{}, err
	}
	return gateway.Identity{
		Subject:          id.Subject,
		Kind:             id.Kind,
		Org:              id.Org,
		ResponsibleHuman: id.ResponsibleHuman,
		Scopes:           id.Scopes,
		Products:         id.Products,
	}, nil
}

// routeProducts gates each pillar prefix by its CWB product. herald is core
// (absent → never gated). Stable platform topology, not per-deploy config.
var routeProducts = map[string]string{
	"/cairn":     "cairn",
	"/ledger":    "ledger",
	"/knowledge": "commonplace",
}

// parseRoutes parses "prefix=backend,prefix=backend" into a map.
func parseRoutes(s string) (map[string]string, error) {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		k, v, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return nil, &parseError{entry}
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

type parseError struct{ entry string }

func (e *parseError) Error() string {
	return "bad route entry (want prefix=backend): " + e.entry
}

// parsePublicPaths splits a comma-separated list into trimmed, non-empty entries.
func parsePublicPaths(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
