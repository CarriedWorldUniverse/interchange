# interchange

[![CI](https://github.com/CarriedWorldUniverse/interchange/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CarriedWorldUniverse/interchange/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/CarriedWorldUniverse/interchange?include_prereleases&sort=semver&display_name=tag)](https://github.com/CarriedWorldUniverse/interchange/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/CarriedWorldUniverse/interchange.svg)](https://pkg.go.dev/github.com/CarriedWorldUniverse/interchange)
[![License](https://img.shields.io/github/license/CarriedWorldUniverse/interchange)](LICENSE)

**The CWB boundary gateway** — the single public edge fronting the Carried
World Builder platform pillars. interchange is two binaries with two concerns:
`cmd/interchange-gateway` (the gateway, now the primary role) and
`cmd/interchange` (the original E2E pair-relay, still here).

This is single-operator R&D. The gateway is the live front door; the relay is
the earlier Frame-to-Frame transport that the project grew out of.

## interchange-gateway — the CWB front door

`cmd/interchange-gateway` is a single auth-aware reverse proxy. One public
entry point; every request is routed by path-prefix to a backend pillar,
authenticated against herald, and proxied with the **verified** identity
injected as trusted `X-CWB-*` headers (or `cwb-*` gRPC metadata) so backends
need not re-verify. It is the only thing on the public edge; the pillars sit
behind it on the cluster, reachable only over the mTLS hop from the gateway.

It fronts the four pillars — **herald** (identity), **cairn** (git),
**ledger** (tracker), **commonplace** (knowledge) — over two mechanisms:

- **Reverse-proxy routes** (`INTERCHANGE_ROUTES`, longest-prefix match) for
  HTTP backends — e.g. the composite **`/herald`** edge (OIDC passthrough:
  `.well-known`, `/jwks`, `/token`, `/revoke` pass unauthenticated for the
  OIDC bootstrap; admin gRPC behind it) and the **`/cairn`** edge (the gRPC
  JSON API plus a git **reverse-proxy** for Smart-HTTP clone/push).
- **grpc-gateway translation** for the gRPC-only pillars — **`/ledger`**
  (Issue / Project / Org / Admin) and **`/knowledge`** (commonplace
  Store / Search) — where the gateway terminates HTTP/JSON and speaks gRPC
  over mTLS to the backend (`INTERCHANGE_LEDGER_GRPC`,
  `INTERCHANGE_COMMONPLACE_GRPC`).

Auth is local JWKS verification via herald's `heraldauth`, with per-org
product entitlement enforced. `INTERCHANGE_PUBLIC_PATHS` lists paths that skip
bearer verification (routing + anti-spoof still apply);
`INTERCHANGE_AUTH_BYPASS=1` is the standalone/dev mode.

**HA:** deployed `replicas: 2` with a PodDisruptionBudget (`minAvailable: 1`)
so the front door is never fully down across pod crashes or rolling updates
(NEX-428); graceful SIGTERM/SIGINT drain on shutdown.

Config is via env — see the header of
[`cmd/interchange-gateway/main.go`](./cmd/interchange-gateway/main.go) for the
full set (`INTERCHANGE_ADDR`, `INTERCHANGE_ROUTES`,
`INTERCHANGE_HERALD_ISSUER` / `_JWKS_URL`, the `_GRPC` backends, and the
`INTERCHANGE_TLS_*` mTLS pair). k3s manifests live under
[`deploy/k3s`](./deploy/k3s).

```sh
go build ./cmd/interchange-gateway
```

## interchange (relay) — E2E Frame-to-Frame ciphertext

`cmd/interchange` is the original concern: a small Go server that relays
signed, end-to-end encrypted envelopes between paired Nexus Frames. It cannot
read message content; it only routes ciphertext between the two ends of a
pair, gates pair establishment behind operator approval, and evicts old
envelopes after a retention window.

Wire protocol: [`docs/spec.md`](./docs/spec.md). Client library (Go):
[`CarriedWorldUniverse/casket`](https://github.com/CarriedWorldUniverse/casket).

### What a Nexus needs to connect

1. A casket `Channel` for its own identity (Ed25519 signing key + ECDH key for body encryption).
2. A paired `Channel` per peer, established via the staged-approval pair flow (operator-gated on the receiving side).
3. HTTP access to an interchange deployment. All interaction is six endpoints:

   - `GET  /.well-known/nexus-interchange` — discovery doc (capabilities, algorithms, endpoints)
   - `POST /pair/request` — submit a signed half, blocks until owner decides
   - `GET  /pair/requests/:id` — poll request state (pending / approved / denied)
   - `POST /pair/requests/:id/approve` *and* `POST /pair/requests/:id/deny` — owner-side actions, **tailnet-only listener**
   - `PUT  /mailbox/:pathId` — send an envelope
   - `GET  /mailbox/:pathId?since=<msg_id>` — receive
   - `POST /mailbox/:pathId/ack` — acknowledge receipt

See [`docs/spec.md`](./docs/spec.md) for envelope format, signing, content handling rules, and the full pairing workflow.

### Topology opacity

A Nexus implementing the client side knows *how* to call the endpoints. It does not know *what* is behind them — a single binary on a tailnet host, a load-balanced fleet, a self-hosted relay run by a third party. The wire protocol is the contract; deployment is opaque.

### Run the relay

```sh
go build ./cmd/interchange
./interchange
```

Two listeners come up by default:

- **`:8443`** — public-facing (mailbox PUT/GET/ack, pair request/poll, discovery). Bind behind TLS / a Tailscale Funnel for production.
- **`:8444`** — tailnet-only (pair approve/deny). Bind to your tailnet interface (e.g. `tailscale0`) so only operators on the tailnet can approve pair requests.

Configure listener addresses, storage path, and retention via env vars or flags — see `cmd/interchange/main.go`.

## Storage

SQLite (pure-Go via `modernc.org/sqlite`, no CGO). The relay schema is embedded in `internal/storage/sqlite.go` and applied on startup with `IF NOT EXISTS` — no separate migration step. Three tables: `envelopes`, `pair_requests`, `pairs`.

## Build and test

Requires Go 1.26+.

```sh
go build ./cmd/...
go test ./...
```

## Stack position

`herald` (identity) · `cairn` (git) · `ledger` (tracker) · `commonplace` (knowledge) · **`interchange` (gateway + relay)**

## License

MIT.
