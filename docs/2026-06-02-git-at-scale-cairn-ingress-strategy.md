# Git at scale through interchange — cairn ingress strategy (design note)

**Date:** 2026-06-02
**Status:** Design note (not a committed plan). Captures the trade-offs behind routing cairn's git traffic through interchange and the levers for scale.
**Context:** cairn is ClusterIP-only and reached via interchange. Question raised: with cairn not directly routed, can interchange handle git — and at scale?

## 1. The question

cairn's git can reach clients two ways:
- **Smart-HTTP** (`clone`/`fetch`/`push` over HTTPS) — proxied through interchange's `/cairn` lane to cairn's HTTP server (`:8100`).
- **SSH** (`ssh://git@<host>:2222`) — cairn's **own LoadBalancer ingress**, a direct external route that does **not** traverse interchange.

So "cairn behind interchange" is only true for the HTTP-git lane. The byte-heavy path already has a non-proxied door (SSH).

## 2. Correctness (settled)

Routing Smart-HTTP through `httputil.ReverseProxy` is correct:
- The proxy **streams** — request body (`git-receive-pack`/`git-upload-pack` packs) is `io.Copy`'d, never fully buffered; chunked/side-band responses (Content-Length unknown) flush per-write.
- interchange only inspects the `Authorization` header (verify herald JWT locally, inject `X-CWB-*`); it does not read the body.
- Proven live: the conformance `HTTPSCloneViaGateway` subtest clones through the gateway. Push uses the same lane.

cairn therefore needs **no directly-routable IP** for HTTP git to function. Phase 3 keeps this exact shape (composite `/cairn`: `/api/` → gRPC, `.git` → reverse-proxy); git is permanently HTTP and never gRPC.

## 3. Scale — the real concerns

Routing all HTTP git through interchange makes it a **byte funnel**. Today's posture amplifies it:

- **`replicas: 1`, no resource limits** (`deploy/k3s/20-deployment.yaml`). Every clone/push holds a goroutine + a backend connection for the full transfer; all git bytes cross one pod's NIC. Bandwidth + connection-count ceiling, and a single point of failure. CI fan-out on a large repo saturates the one pod.
- **No server timeouts** (`http.ListenAndServe` default). Long clones aren't cut off (good), but there's no slowloris protection and no resource cap — a burst can starve node neighbours.
- **Cloudflare body limit.** Per the edge topology (CF → ALB/Tunnel → interchange), CF's proxy caps request bodies (~100 MB on non-Enterprise). Large `git push` over HTTPS-through-CF can fail — independent of interchange.

Working in our favour: interchange is **stateless** (local JWKS verify + header inject) and does almost no CPU (cairn's `git-upload-pack` does the pack computation). The funnel is bandwidth/connection-bound, not compute-bound — so horizontal scale-out is cheap and effective.

## 4. Strategy (ordered levers)

1. **Prefer SSH for heavy/automated git** (CI, aspects). Already bypasses interchange on its own LB; pubkey auth via herald `by-fingerprint`. The high-volume path is already off the funnel — make it the default for automation.
2. **Make interchange horizontally scalable + bounded.** `replicas: N` behind the Service (stateless → trivial), add resource requests/limits, a PodDisruptionBudget, and a readiness gate for rolling. `replicas: 1` is the actual near-term bottleneck/SPOF, independent of the git question. *(Ticket filed — see §6.)*
3. **If HTTPS git must scale, give the `.git` lane its own ingress that bypasses the gateway.** cairn verifies the bearer itself via `heraldauth` (like every other consumer). The Phase-3 composite design deliberately keeps git on a *separable* reverse-proxy lane precisely so it can be split to a dedicated ingress later without touching the gRPC API lane.
4. **Mind the CF body cap** for HTTPS pushes — Enterprise raises it; or route git via Cloudflare Tunnel / a direct git ingress / SSH.

## 5. Bottom line

For the MVP target (the nexus team — modest concurrency), proxied cairn through interchange is correct and adequate. It is **not** the right shape for high-volume public git. The architecture already has the escape hatches: SSH is direct, the git HTTP lane is separable from the API lane, and the gateway is stateless so it scales out. The scaling move is to **stop funneling git through interchange** (SSH-first + a dedicated git ingress), not to make one gateway carry every byte. Near term, the only acute issue is `replicas: 1` — fix that regardless.

## 6. Follow-up

- Ticket: interchange HA — `replicas > 1`, resource requests/limits, PDB (near-term SPOF fix; not git-specific).
- Deferred (this note is the rationale): dedicated git-HTTP ingress bypassing the gateway; SSH-first guidance for CI/aspects; CF body-limit handling for HTTPS push.
