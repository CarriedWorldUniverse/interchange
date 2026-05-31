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
//	INTERCHANGE_ADDR           listen addr (default :8080)
//	INTERCHANGE_ROUTES         "prefix=backend,prefix=backend,..." e.g.
//	                           "/herald=http://herald:8099,/ledger=http://ledger:8080"
//	INTERCHANGE_HERALD_ISSUER  herald issuer URL (required unless bypass) — for JWKS verify
//	INTERCHANGE_HERALD_JWKS_URL optional override pointing heraldauth at an
//	                           internal JWKS endpoint instead of going through
//	                           discovery on the public issuer. Use this when
//	                           the gateway is fronting its own issuer to avoid
//	                           a boot loop calling itself, e.g.
//	                             INTERCHANGE_HERALD_JWKS_URL=http://herald.cwb.svc:8099/jwks
//	INTERCHANGE_AUTH_BYPASS    "1" to skip auth (mode-1 standalone)
//	INTERCHANGE_PUBLIC_PATHS   "path,path,..." gateway-side paths that skip
//	                           bearer-token verification (routing + anti-spoof
//	                           still apply). Entries ending in "/" are prefix
//	                           matches, e.g.
//	                             "/herald/.well-known/,/herald/jwks"
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/CarriedWorldUniverse/herald/heraldauth"
	"github.com/CarriedWorldUniverse/interchange/internal/gateway"
)

func main() {
	addr := env("INTERCHANGE_ADDR", ":8080")
	bypass := os.Getenv("INTERCHANGE_AUTH_BYPASS") == "1"

	routes, err := parseRoutes(os.Getenv("INTERCHANGE_ROUTES"))
	if err != nil {
		log.Fatalf("interchange-gateway: routes: %v", err)
	}
	if len(routes) == 0 {
		log.Fatal("interchange-gateway: INTERCHANGE_ROUTES is empty (nothing to proxy)")
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

	g, err := gateway.New(gateway.Config{
		Verifier:      verifier,
		AuthBypass:    bypass,
		Routes:        routes,
		PublicPaths:   publicPaths,
		RouteProducts: routeProducts,
	})
	if err != nil {
		log.Fatalf("interchange-gateway: %v", err)
	}

	log.Printf("interchange-gateway listening on %s (bypass=%v, routes=%d, public_paths=%d)", addr, bypass, len(routes), len(publicPaths))
	if err := http.ListenAndServe(addr, g.Handler()); err != nil {
		log.Fatalf("interchange-gateway: %v", err)
	}
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
