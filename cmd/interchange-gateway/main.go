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
//	INTERCHANGE_AUTH_BYPASS    "1" to skip auth (mode-1 standalone)
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
		hv, err := heraldauth.New(context.Background(), heraldauth.Config{Issuer: issuer})
		if err != nil {
			log.Fatalf("interchange-gateway: herald verifier (issuer=%s): %v", issuer, err)
		}
		verifier = heraldVerifier{hv}
	}

	g, err := gateway.New(gateway.Config{Verifier: verifier, AuthBypass: bypass, Routes: routes})
	if err != nil {
		log.Fatalf("interchange-gateway: %v", err)
	}

	log.Printf("interchange-gateway listening on %s (bypass=%v, routes=%d)", addr, bypass, len(routes))
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
	}, nil
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

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
