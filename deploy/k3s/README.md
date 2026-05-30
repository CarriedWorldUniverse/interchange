# interchange-gateway — k3s manifests

The CWB platform front door. The only externally-reachable service in the
`cwb` namespace; all backends are `ClusterIP`-only.

## Prerequisite

- `cwb` namespace exists (created by herald's manifests, or apply
  `herald/deploy/k3s/00-namespace.yaml`).
- `herald.cwb.svc:8099` resolves (deploy herald first so the issuer URL works
  at startup — heraldauth fetches JWKS during construction).

## Apply

```sh
kubectl apply -f deploy/k3s/
kubectl -n cwb rollout status deploy/interchange-gateway
kubectl -n cwb get svc interchange-gateway
```

`servicelb` (klipper) will allocate the node's IP on port 8080 as
`EXTERNAL-IP`. On dMon that's the tailscale IP (e.g. `100.70.156.32:8080`).

## Smoke

```sh
GW=$(kubectl -n cwb get svc interchange-gateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# gateway's own healthz (not proxied)
curl -sS "http://$GW:8080/healthz"

# herald OIDC discovery via gateway — public (heraldauth always lets the
# .well-known + /jwks paths through? otherwise expect 401 from gateway since
# this isn't a configured "no-auth" path). If gateway gates discovery, see
# notes below — initial deploy may need INTERCHANGE_AUTH_BYPASS=1 or a
# bypass-path config to expose the issuer to consumers.
curl -sS "http://$GW:8080/herald/.well-known/openid-configuration"
```

## Auth contract

- `INTERCHANGE_ROUTES` — `prefix=backend,...` (longest prefix wins,
  prefix-stripped before proxy).
- `INTERCHANGE_HERALD_ISSUER` — must match herald's `HERALD_ISSUER` exactly;
  the gateway calls `heraldauth.New` against this issuer at startup.
- Requests without a valid bearer get `401`. Verified callers get the
  identity stamped in `X-CWB-{Org,Subject,Kind,Scopes}` headers and proxied
  to the backend.
- `INTERCHANGE_AUTH_BYPASS=1` — bypass auth entirely (mode-1 / standalone).
  Useful for the very first smoke before any humans/agents exist in herald.
