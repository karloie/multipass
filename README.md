# ✅️ Multipass

[![CI](https://github.com/karloie/multipass/actions/workflows/ci.yml/badge.svg)](https://github.com/karloie/multipass/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/karloie/multipass.svg)](https://pkg.go.dev/github.com/karloie/multipass)
[![Go Report Card](https://goreportcard.com/badge/github.com/karloie/multipass)](https://goreportcard.com/report/github.com/karloie/multipass)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/karloie/multipass)](https://hub.docker.com/r/karloie/multipass)

<img src="doc/vibecoded.png" width="120" alt="Vibe Coded Badge" align="right">

**Grafana-opinionated authenticating and authorizing reverse proxy**

Multipass is an opinionated authenticating and authorizing reverse proxy for Grafana and the observability systems around it. It puts OIDC login, authorization, tenant isolation, and auditability at the edge, so Grafana and upstream backends do not each need their own authentication and authorization setup.

It handles browser authentication with OIDC, evaluates authorization from token claims, and forwards the headers or tokens each backend expects. In front of Grafana, Prometheus, Loki, Mimir, Tempo, OpenSearch, Kibana, VictoriaMetrics, and similar systems, Multipass becomes the single control point for access.

It runs in two modes:

1. **web** for browser-based tools and dashboards.
2. **api** for programmatic systems that expect tokens or trusted headers.

Single sign-on. Token-driven authz. Tenant isolation. Label-matching isolation. Full audit trail. Zero backend changes.

## Why Multipass?

Observability and operations tools rarely agree on how access should work. One wants OIDC, another expects headers, another wants JWTs. The result is duplicated setup, uneven access control, and too much backend-specific glue.

Multipass solves that at the edge:

- **OIDC SSO** — one browser login flow across the stack
- **OIDC and token authz** — authenticate with OIDC and authorize directly from validated token claims
- **Two delivery modes** — web for UI-oriented tools, api for systems that expect tokens or headers
- **Tenant-level isolation** — route requests into the right tenant and inject backend-native tenant headers such as `X-Scope-OrgID`
- **Label-matching isolation** — constrain Prometheus-style queries with `queryRewrite.tenantLabel` or explicit semantic rewrite rules
- **Backend translation** — tenant headers, JWT passthrough, or trusted web headers depending on what the backend expects
- **Data minimization** — keep identity, authorization, and audit decisions at the edge without pulling more backend data into Multipass than necessary
- **Auditability** — access decisions logged in one place and easy to ship onward

## What It Enforces

- **Authentication**: browser and API access start with OIDC-backed identity
- **Authorization**: tenant access is evaluated from token groups through `authz`
- **Tenant isolation**: Prometheus-compatible backends can be fixed to a tenant or request-routed to one tenant at a time
- **Query isolation**: PromQL and selector-style requests can be rewritten so required label matchers are validated or appended before the request reaches the backend

This means Multipass can enforce both coarse tenant boundaries and fine-grained label boundaries in front of shared observability backends.

### Backend Types

- `prometheus` — for Prometheus-compatible APIs such as Loki, Mimir, Tempo, Prometheus, Thanos, and VictoriaMetrics. This is the main path for tenant-level isolation because Multipass can resolve a tenant, inject `X-Scope-OrgID`, and apply query rewrites for label-matching isolation.
- `jwt` — for backends that should receive the caller's original bearer token. Use this when the upstream system already has its own JWT/OIDC-aware RBAC and Multipass should stay focused on authentication, edge authorization, and routing.
- `generic` — for simple reverse proxying where the backend does not need tenant headers or token projection. This is the low-opinion path for static-header forwarding and plain request routing.
- `web` — for browser-facing tools that trust identity headers from the proxy. Use this for dashboards and admin UIs where Multipass should handle OIDC login and pass user, email, groups, or role-like headers to the upstream app.

See [doc/API.md](doc/API.md).

For Prometheus-style backends, the important combination is:

- `auth.provider: oidc`
- `authz.provider: token`
- request or fixed namespace routing
- `queryRewrite.tenantLabel` or `queryRewrite.semantics`

That gives you OIDC authentication, token-based authorization, tenant-level routing, and label-matching isolation in one proxy layer.

## Architecture

Multipass sits both in front of Grafana for browser sign-in and on the datasource path between Grafana or API clients and the LGTM backends.

```
        Browser users
            |
            | web login + session
            v
    +-----------------+        +---------------+
    |    Multipass    |------->| OIDC provider |
    |  browser edge   |        +---------------+
    +-----------------+
            |
            | trusted user headers
            v
        +---------+
        | Grafana |
        +---------+
            |
            | datasource proxy
            v
  +-------------------+        +------------+
  |     Multipass     |------->| Audit sink |
  |  datasource edge  |        +------------+
  +-------------------+
    v       v       v
+------+ +-------+ +-------+
| Loki | | Mimir | | Tempo |
+------+ +-------+ +-------+
```
## Configuration

See [config.example.yaml](config.example.yaml) for complete examples.

For a realistic local profile backed by an external OIDC provider, use
[config.oidc.yaml](config.oidc.yaml). This keeps Multipass on `oidc` and
`token`, so moving from local OIDC to production OIDC is mostly an issuer and client
configuration change instead of a provider swap.

Start Multipass by passing exactly one config file argument:

```bash
./multipass config.oidc.yaml
go run ./cmd/multipass config.oidc.yaml
```

### URL Routing

Requests are routed by backend name: `http://multipass:8080/<backend>/<path>`

- `http://multipass:8080/loki/loki/api/v1/query` → `http://loki:3100/loki/api/v1/query`
- `http://multipass:8080/grafana/api/dashboards` → `http://grafana:3000/api/dashboards`

## Deployment

- edit [k8s/configmap.yaml](k8s/configmap.yaml)
- deploy with `kubectl apply -f k8s/`
- use `kubectl apply -k k8s/oidc/` for the in-cluster OIDC overlay

## Development

See [doc/DEV.md](doc/DEV.md).

## License

MIT
