# interchange-gateway — MVP Spec

**Status:** draft · 2026-05-30 (built overnight for morning k3s deploy)
**Goal:** a single-ingress, auth-aware reverse proxy — the **front door of the Carried World Builder (CWB) platform**. One public entry point that authenticates callers via herald and routes to the backend services (herald, cairn, ledger, commonplace).

This is **interchange-gateway** — a *new, separate* binary (`cmd/interchange-gateway`) in the interchange repo. The existing `cmd/interchange` (E2E pair-relay) is **untouched** (two-binary plan from the respec). The webhook **push-relay** is explicitly **out of this MVP** — the proxy is what forces clients through the auth boundary, which is what the k3s-isolation test needs; the relay is a separate later build.

## 1. What it does (one paragraph)

interchange-gateway listens on one address. Every request: (a) match a route by path-prefix to a backend service; (b) unless in bypass mode, extract the bearer token and verify it locally via `heraldauth` (cached JWKS — no per-request call to herald), rejecting unauthenticated/expired tokens with 401; (c) inject the *verified* identity (org, subject, kind, scopes) as trusted headers onto the proxied request so the backend doesn't re-verify; (d) reverse-proxy to the backend. In **bypass mode** (`INTERCHANGE_AUTH_BYPASS=1`, the mode-1 / standalone posture) it skips auth and proxies straight through. It is the single door: backends are otherwise unreachable (ClusterIP in k3s), so all client→service traffic traverses the gateway with real auth.

```
  client (nexus / any) ──▶ interchange-gateway ──route+auth──▶ herald | cairn | ledger | commonplace
                              (the only public surface)         (ClusterIP, unreachable except via here)
```

## 2. In scope (MVP)

1. **Route table** — path-prefix → backend URL. Config-driven (env or a small config file). e.g. `/herald/* → http://herald:8099`, `/ledger/* → http://ledger:8080`, etc. Strips the prefix before proxying (or not — configurable per route).
2. **herald auth middleware** — `heraldauth.Verify(token)` on the bearer; 401 on missing/invalid/expired. Verified `Identity` → injected headers (`X-CWB-Org`, `X-CWB-Subject`, `X-CWB-Kind`, `X-CWB-Scopes`). Strips any client-supplied `X-CWB-*` headers first (anti-spoof).
3. **Bypass mode** — `INTERCHANGE_AUTH_BYPASS=1` skips auth entirely (mode-1 standalone). Logged loudly at boot.
4. **Reverse proxy** — `httputil.ReverseProxy` per backend; preserves method/body/query; sane timeouts; 502 on backend down; 404 on no route match.
5. **Health** — `GET /healthz` (gateway's own; not proxied).
6. **Wired binary + config** — `cmd/interchange-gateway`, env-configured (`INTERCHANGE_ADDR`, `INTERCHANGE_HERALD_ISSUER`, `INTERCHANGE_ROUTES`, `INTERCHANGE_AUTH_BYPASS`), e2e smoke (fake herald issues a token + fake backend; assert authed routes through with injected identity, unauthed 401, bypass passes, no-route 404, header-spoof stripped).

## 3. Out of scope (MVP — deferred)

- **Push/webhook relay** (the persistent-connection channel for server→private-nexus). Separate hard piece; not needed for the auth-boundary test.
- **TLS termination** — k3s ingress controller / a fronting proxy handles public TLS; the gateway runs HTTP inside the cluster for v1 (revisit for direct exposure).
- **Per-route scope enforcement** — MVP injects scopes; backends enforce. (Gateway-level coarse scope gates are a fast-follow.)
- **Rate limiting, outbound proxy, signature-verified webhook ingress** — later.

## 4. Route config shape

`INTERCHANGE_ROUTES` = a compact spec, e.g.:
```
/herald=http://herald:8099,/ledger=http://ledger:8080,/cairn=http://cairn:3000,/commonplace=http://commonplace:8090
```
Each entry `prefix=backend`. Prefix is stripped before proxying (so `/herald/jwks` → `herald:8099/jwks`). A `=keep` suffix could preserve the prefix if a backend expects it (decide per backend during deploy).

## 5. Auth flow (per request, non-bypass)

1. Match longest path-prefix → backend (404 if none).
2. `/healthz` short-circuits (gateway health).
3. Strip inbound `X-CWB-*` headers (anti-spoof).
4. Extract `Authorization: Bearer <tok>`; 401 if absent.
5. `id, err := verifier.Verify(ctx, tok)`; 401 if err.
6. Inject `X-CWB-Org/Subject/Kind/Scopes` from `id`.
7. ReverseProxy to backend.

## 6. Build sequence (TDD, PR-per-task, CI-gated — herald pattern)

1. **gateway scaffold** — `cmd/interchange-gateway` + `internal/gateway` pkg + `/healthz`; CI already exists.
2. **route table + reverse proxy** — parse `INTERCHANGE_ROUTES`, prefix-match, proxy; tests: route match, prefix strip, 404 no-route, 502 backend-down.
3. **herald auth middleware** — heraldauth verify, 401s, header inject + spoof-strip, bypass mode; tests against a fake/real herald token.
4. **wire `cmd/interchange-gateway`** + e2e smoke (fake herald + fake backend through the gateway).
5. **container image** (Dockerfile/Containerfile) — tiny static Go binary, ready for `podman build` → k3s.

## 7. Definition of done (MVP)

A request with a valid herald token routes through the gateway to a backend, arriving with trusted `X-CWB-*` identity headers; an unauthenticated request gets 401; bypass mode passes through; a spoofed `X-CWB-*` header from the client is stripped. Containerized, ready to drop into the morning's k3s deploy as the single ingress in front of herald.
