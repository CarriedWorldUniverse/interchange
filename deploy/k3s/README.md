# interchange-gateway — k3s manifests

The CWB platform front door. The only externally-reachable service in the
`cwb` namespace; all backends are `ClusterIP`-only.

## Prerequisites

- `cwb` namespace exists (created by herald's manifests, or apply
  `herald/deploy/k3s/00-namespace.yaml`).
- `herald.cwb.svc:8099` resolves (deploy herald first so the issuer URL works
  at startup — heraldauth fetches JWKS during construction).
- **cert-manager** is installed, and the shared internal CA + `interchange-client-tls`
  secret have been created. Apply `commonplace/deploy/k3s/05-certs.yaml` first
  (it owns the CA and both leaf certs).

## Apply

```sh
# Cert-manager CRs first (from commonplace repo):
kubectl apply -f /path/to/commonplace/deploy/k3s/05-certs.yaml
kubectl -n cwb wait --for=condition=Ready certificate/interchange-client-tls --timeout=120s

kubectl apply -f deploy/k3s/
kubectl -n cwb rollout status deploy/interchange-gateway
kubectl -n cwb get svc interchange-gateway
```

`servicelb` (klipper) will allocate the node's IP on port 8080 as
`EXTERNAL-IP`. On dMon that's the tailscale IP (e.g. `100.91.185.71:8080`).

## gRPC edge

`/knowledge` requests are **not** in `INTERCHANGE_ROUTES` — they are translated
to gRPC calls against `commonplace.cwb.svc:8101` via
`INTERCHANGE_COMMONPLACE_GRPC`. The same grpc-gateway pattern serves `/ledger`
(`INTERCHANGE_LEDGER_GRPC`), `/almanac` (`INTERCHANGE_ALMANAC_GRPC` —
Config/Secret/AlmanacAdmin services) and `/mason` (`INTERCHANGE_MASON_GRPC` —
AppService). Interchange uses the `interchange-client-tls`
cert (mounted at `/etc/cwb/tls`) for mTLS. Interchange's own listener stays
plain HTTP on `:8080`.

## Smoke

```sh
GW=$(kubectl -n cwb get svc interchange-gateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# gateway's own healthz (not proxied)
curl -sS "http://$GW:8080/healthz"

# herald OIDC discovery via gateway — public path
curl -sS "http://$GW:8080/herald/.well-known/openid-configuration"
```

## Auth contract

- `INTERCHANGE_ROUTES` — `prefix=backend,...` (longest prefix wins,
  prefix-stripped before proxy). `/knowledge` is absent; handled by gRPC edge.
- `INTERCHANGE_HERALD_ISSUER` — must match herald's `HERALD_ISSUER` exactly;
  the gateway calls `heraldauth.New` against this issuer at startup.
- Requests without a valid bearer get `401`. Verified callers get the
  identity stamped in `X-CWB-{Org,Subject,Kind,Scopes}` headers and proxied
  to the backend.
- `INTERCHANGE_AUTH_BYPASS=1` — bypass auth entirely (mode-1 / standalone).
  Useful for the very first smoke before any humans/agents exist in herald.
