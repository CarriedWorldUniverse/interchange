# CWB gRPC mesh — Phase 4: herald (spec)

**Date:** 2026-06-02
**Status:** Proposed — pre-implementation, awaiting operator review.
**Parent:** `docs/2026-06-01-cwb-grpc-backend-architecture-design.md`. Builds on Phases 1–3 (commonplace/ledger/cairn) — reuses cwb-proto/buf, the interchange `edge` pkg + `newGRPCMux`, the composite-edge pattern (from cairn, Phase 3), cert-manager mTLS, and the conventions (`UseProtoNames`, `response_body`, last-registered route ordering, `*_DEV_INSECURE` opt-in, deploy-via-`kubectl patch`).

## 1. Goal

Migrate herald's **admin/internal API to gRPC** behind interchange, while:
- keeping the **OIDC surface HTTP** (discovery, JWKS, `/token`) — interchange and external clients consume it to verify/mint tokens *before* any token exists, so it can never be gRPC (HTTP-passthrough forever, like cairn's git lane);
- **replacing the static `HERALD_ADMIN_TOKEN`** with **identity-derived, org-scoped admin authorization** — admin authority comes from the authenticated principal's role *for the target org*, carried in its herald JWT and enforced by herald;
- seeding the root via a **deploy-time owning org + owner account** (`cwadmin@carriedworld.com`) — **no static admin token, no default accounts or override passwords shipped in code**.

herald is the load-bearing pillar (every token verify depends on it) and dual-faced, so it migrates last.

## 2. herald's two faces after Phase 4

| Face | Transport | Why |
|---|---|---|
| **OIDC** — `GET /.well-known/openid-configuration`, `GET /jwks`, `POST /token` (jwt-bearer + password grants) | **HTTP** (interchange passthrough) | OIDC is an HTTP standard; interchange itself fetches JWKS over HTTP to verify every token. Bootstrapping auth can't require auth. |
| **Admin/internal API** — org/human/agent provisioning, products, list-orgs, DeleteOrg | **gRPC** behind interchange (JWT-authed, identity-derived authz) | The migration target. |
| **by-fingerprint** — `GetAgentByFingerprint` | **gRPC, mTLS-authed, internal** (cairn dials herald directly) | Consumed by cairn's SSH path, where the client presents a **pubkey, not a token** — there is no herald JWT to verify, so it's an in-cluster service lookup authorized by the mTLS client cert (cwb-ca), not routed through the JWT edge. |

## 3. Authorization model (replaces the static admin token)

herald JWTs already carry `sub`, `act.sub` (responsible human), `org`, `scope`, fingerprints. Add an **admin authority** expressed as scopes, verified by interchange (JWKS) and injected as `cwb-*` metadata; herald enforces against the **target** org:

- **`herald:platform-admin`** — held only by the owning org's owner account. May `CreateOrg`, `ListOrgs` (all), `DeleteOrg` (any), and admin any org. This is the platform root.
- **`herald:org-admin`** — held by an org's administrators, **bound to the token's `org` claim**. May provision humans/agents, set passwords, issue tokens, and toggle products **within their own org only** — i.e. an op on org X requires `cwb-org == X` (or `herald:platform-admin`).

Enforcement rule per RPC: `platform-admin` ⇒ allow any org; else require `herald:org-admin` **and** `target_org == cwb-org`. herald is a **core** product, so interchange's product-entitlement gate exempts `/herald` (no `cwb-products` check).

**Domain separation (load-bearing invariant).** The admin org is the *administration* domain; working/tenant orgs are the tenant domain — and the two are **disjoint**:
- An identity belongs to exactly one org. **Admin-org accounts can NOT be members of, or act within, any working org**, and **working-org accounts can never hold `herald:platform-admin`**. herald rejects any attempt to add an admin-org principal to a working org (and vice-versa for granting platform-admin).
- `herald:platform-admin` confers **platform + org-lifecycle authority only** (create / list / delete orgs, products, platform management) — it is **NOT** tenant-data access. A platform admin is never an org *member*, so the pillars' org-scoped data (cairn repos, ledger issues, commonplace knowledge) is **not** reachable by an admin-org identity through membership. Managing an org's *existence* ≠ reading its *contents*. This keeps the platform root from being a backdoor into every tenant's data.

Self-serve "any authenticated user creates an org and becomes its admin" is **deferred** (commercial layer); for the MVP, `CreateOrg` is `platform-admin`-gated. The richer NEX-413 org-ownership features (invites, domain verification, hosted/trusted tiers) are **out of scope** here — Phase 4 lands only the authz *spine*.

## 4. Genesis — the admin (administration) org (deploy-time, no shipped credentials)

The genesis root is a dedicated **administration org** whose purpose is to **support the deploy + platform operations** — it is NOT a general working org. A deploy-time provisioning step (a herald init mode or a one-shot Job) creates, **idempotently**:
1. the **admin org** (the platform administration org), and
2. the **platform-admin account** `cwadmin@carriedworld.com` (a human identity in the admin org) granted **`herald:platform-admin`**,

with credentials (password and/or a casket key) supplied from a **k8s Secret / deploy config at apply time** — never from the image or source. If the admin org/account already exists, the step is a no-op (no credential reset). The owner then authenticates via the normal flows (path-A password grant or casket assertion) to obtain a `herald:platform-admin` token and administers the platform + provisions working orgs through the gateway.

Per §3, admin-org accounts are **firewalled from working orgs** (platform administration only — never tenant members).

**Platform-management tooling** (operating the deploy, managing orgs/quotas/health from the admin org) **lives in herald** and will be built out **later** — Phase 4 only establishes the admin org + the platform-admin authority it runs on.

**Removed:** `HERALD_ADMIN_TOKEN` and the `adminapi` static-token comparison path. There is no break-glass shared secret and no default/seeded password in code.

## 5. cwb-proto `herald.v1`

New package **`cwb.herald.v1`** (own package, mirroring the cairn precedent; avoids name clashes with the shared `cwb.v1`). Services + `google.api.http` annotations mirroring the live admin routes under `/api/...`, with `response_body` to keep flat REST JSON:

- **AdminService**: `CreateOrg`, `ListOrgs`, `CreateHuman` (`POST /api/orgs/{org}/humans`), `CreateAgent` (`POST /api/orgs/{org}/agents`), `SetHumanPassword`, `IssueHumanToken`, `EnableProduct`/`DisableProduct`/`GetProducts`, `DeleteOrg`.
- **AgentService** (internal): `GetAgentByFingerprint`, `ValidateAgent`. (`GetAgentByFingerprint` is the mTLS-internal one — see §6.)

OIDC is **not** modeled in proto (stays HTTP). Token format is unchanged (signed EdDSA JWT; the purge token herald mints is untouched).

## 6. herald server shape

herald runs **both** servers (like cairn is dual-transport):
- **HTTP** (`:8099`, unchanged): OIDC discovery/JWKS/`/token` + `/healthz`. Reached via interchange passthrough.
- **gRPC** (new port, mTLS, RequireAndVerifyClientCert vs cwb-ca; `HERALD_DEV_INSECURE=1` opt-in): the admin/internal services.
  - **Admin RPCs**: authorize from `cwb-*` metadata (injected by interchange after JWT verify) per §3. Reject if no verified identity.
  - **`GetAgentByFingerprint`**: authorized by the **mTLS client cert alone** (a valid cwb-ca peer = a trusted in-cluster service); no `cwb-*` identity required. This is the one RPC cairn dials **directly** (not through the interchange JWT edge), because the SSH flow has no token.

## 7. interchange composite `/herald` edge

Like cairn's `/cairn`, `/herald` becomes a **composite** handler:
- `/herald/.well-known/...`, `/herald/jwks`, `/herald/token` → **HTTP passthrough** (reverse-proxy to herald HTTP; these stay in `PublicPaths` — reachable tokenless).
- `/herald/api/...` → **grpc-gateway edge** → mTLS to herald's gRPC AdminService, JWT-authed + `cwb-*` injected (herald is core: no product gate).
- `GetAgentByFingerprint` is **not** exposed on the public edge — it's internal (cairn dials herald gRPC directly). `INTERCHANGE_HERALD_GRPC` (default `herald.cwb.svc:<grpcport>`) for the admin edge; the existing `/herald` reverse-proxy backend is reused for the OIDC passthrough lane.

## 8. Consumers to migrate

- **cairn → by-fingerprint**: `internal/herald` client HTTP → gRPC (mTLS, cwb-ca client cert), dialing herald's gRPC directly. Same `Agents` interface so callers/cache unchanged.
- **herald → pillars purge fan-out (NEX-402)**: **unchanged** — herald already calls each pillar's `DELETE /api/org` through the gateway, which now translates to the pillar's gRPC `PurgeOrg`. (herald's purge client stays HTTP-through-gateway; verified still works.)
- **conformance fixtures**: stop using a static admin token; instead **authenticate as the seeded owner** (`cwadmin@…` password grant → `herald:platform-admin` token) and provision orgs/users via the gRPC admin edge through the gateway. The owning org/owner is seeded in the dMon/CI setup from a secret.

## 9. Certs + manifests

- New **`herald-tls`** cert-manager Certificate: `server auth` + dnsNames (`herald.cwb.svc[.cluster.local]`, `herald`) for the gRPC server. (herald may also need a **client** cert for its purge fan-out, but that path is unchanged/HTTP-through-gateway, so likely not required in Phase 4.)
- herald deployment: add the gRPC port + TLS env/mount + `HERALD_DEV_INSECURE` opt-in; remove `HERALD_ADMIN_TOKEN`; add the genesis owner secret (`cwadmin` credential) + the provisioning step. Keep HTTP `:8099`.
- interchange deployment: `INTERCHANGE_HERALD_GRPC`; `/herald` composite (keep the OIDC reverse-proxy backend for passthrough).
- cairn deployment: add `HERALD_GRPC_ADDR` (+ reuse cairn's cwb-ca client cert) for the by-fingerprint dial; retire `HERALD_BASE_URL` once migrated.

## 10. Conformance / DoD

- `herald.v1` in cwb-proto; herald dual-transport (gRPC admin over mTLS + unchanged HTTP OIDC); identity-derived admin authz; genesis owner seeded from a secret with **no shipped credentials**; `HERALD_ADMIN_TOKEN` removed.
- interchange composite `/herald` routes OIDC→passthrough and `/api/`→gRPC; cairn by-fingerprint over mTLS gRPC.
- Conformance updated: fixtures provision via the seeded owner identity (not a static token); herald layer asserts the admin authz matrix (platform-admin vs org-admin vs cross-org-denied); a herald-gRPC mTLS-refused probe; OIDC + token mint + the full journey stay green.
- `cwb-conform -target dmon -layers all` GREEN. Phase 5 (retire the non-OIDC/non-git HTTP reverse-proxy lanes) remains after.

## 11. Open questions for review

1. **Scope names** — `herald:platform-admin` / `herald:org-admin` ok, or fold into existing scope conventions?
2. **Owner credential type** — password (path-A) seeded from a Secret, casket key, or both? (Leaning: password for the human owner now; casket later.)
3. **`CreateOrg` gating** — platform-admin-only for the MVP (self-serve deferred) — confirm.
4. **Genesis as herald init-mode vs a separate one-shot Job** — implementer's call, or a preference?
