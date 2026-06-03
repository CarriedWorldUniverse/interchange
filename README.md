# interchange

[![CI](https://github.com/CarriedWorldUniverse/interchange/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CarriedWorldUniverse/interchange/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/CarriedWorldUniverse/interchange?include_prereleases&sort=semver&display_name=tag)](https://github.com/CarriedWorldUniverse/interchange/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/CarriedWorldUniverse/interchange.svg)](https://pkg.go.dev/github.com/CarriedWorldUniverse/interchange)
[![License](https://img.shields.io/github/license/CarriedWorldUniverse/interchange)](LICENSE)

Shared E2E-encrypted relay for Nexus Frame-to-Frame communication.

This repository ships two separate binaries with distinct concerns:

- **`cmd/interchange`** — the E2E-encrypted pair-relay described below.
- **`cmd/interchange-gateway`** — the auth-aware reverse proxy that fronts the Carried World Builder (CWB) platform services. It is the single public entry point: it verifies bearer tokens locally against herald's JWKS, injects the verified identity as trusted `X-CWB-*` headers, grpc-gateway-translates the commonplace and ledger RPCs, and reverse-proxies to backends over mTLS. See [`docs/2026-05-30-gateway-mvp-spec.md`](./docs/2026-05-30-gateway-mvp-spec.md) and `cmd/interchange-gateway/main.go`.

The pair-relay (`cmd/interchange`) is a small Go server that relays signed, end-to-end encrypted envelopes between paired Nexus instances. It cannot read message content; it only routes ciphertext between the two ends of a pair, gates pair establishment behind operator approval, and evicts old envelopes after a retention window.

Wire protocol (pair-relay): [`docs/spec.md`](./docs/spec.md).

Client library (Go): [`nexus-cw/casket-go`](https://github.com/nexus-cw/casket-go).

## What a Nexus needs to connect

1. A casket `Channel` for its own identity (Ed25519 signing key + ECDH key for body encryption).
2. A paired `Channel` per peer, established via the staged-approval pair flow (operator-gated on the receiving side).
3. HTTP access to an Interchange deployment. All interaction is six endpoints:

   - `GET  /.well-known/nexus-interchange` — discovery doc (capabilities, algorithms, endpoints)
   - `POST /pair/request` — submit a signed half, blocks until owner decides
   - `GET  /pair/requests/:id` — poll request state (pending / approved / denied)
   - `POST /pair/requests/:id/approve` *and* `POST /pair/requests/:id/deny` — owner-side actions, **tailnet-only listener**
   - `PUT  /mailbox/:pathId` — send an envelope
   - `GET  /mailbox/:pathId?since=<msg_id>` — receive
   - `POST /mailbox/:pathId/ack` — acknowledge receipt

See [`docs/spec.md`](./docs/spec.md) for envelope format, signing, content handling rules, and the full pairing workflow.

## Topology opacity

A Nexus implementing the client side knows *how* to call the endpoints. It does not know *what* is behind them — a single binary on a tailnet host, a load-balanced fleet, a self-hosted relay run by a third party. The wire protocol is the contract; deployment is opaque.

## Build and run (pair-relay)

Requires Go 1.26+.

```sh
go build ./cmd/interchange
./interchange
```

Two listeners come up by default:

- **`:8443`** — public-facing (mailbox PUT/GET/ack, pair request/poll, discovery). Bind behind TLS / a Tailscale Funnel for production.
- **`:8444`** — tailnet-only (pair approve/deny). Bind to your tailnet interface (e.g. `tailscale0`) so only operators on the tailnet can approve pair requests.

Configure listener addresses, storage path, and retention via env vars or flags — see `cmd/interchange/main.go`.

## Storage

SQLite (pure-Go via `modernc.org/sqlite`, no CGO). Schema is embedded in `internal/storage/sqlite.go` and applied on startup with `IF NOT EXISTS` — no separate migration step. Three tables: `envelopes`, `pair_requests`, `pairs`.

## Test

```sh
go test ./...
```

The suite covers the discovery, storage, mailbox, sweep, crypto, pairflow, gateway, edge, middleware, and landing packages. Tests use `httptest` against in-process handlers — no network, no external dependencies.

## Status

Phase 2 of the relay build is complete (discovery, storage, mailbox handlers, retention sweep, Ed25519 verification, full pair flow with tailnet binding). Deployment to dMon and live cross-host handshake testing are the remaining items.

## License

MIT.
