# ✅️ Multipass

[![CI](https://github.com/karloie/multipass/actions/workflows/ci.yml/badge.svg)](https://github.com/karloie/multipass/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/karloie/multipass.svg)](https://pkg.go.dev/github.com/karloie/multipass)
[![Go Report Card](https://goreportcard.com/badge/github.com/karloie/multipass)](https://goreportcard.com/report/github.com/karloie/multipass)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/karloie/multipass)](https://hub.docker.com/r/karloie/multipass)

<img src="https://raw.githubusercontent.com/karloie/multipass/main/doc/vibecoded.png" width="120" alt="Vibe Coded Badge" align="right">

**Grafana-opinionated authenticating and authorizing reverse proxy**

Multipass is an opinionated authenticating and authorizing reverse proxy for Grafana and the observability systems around it. It puts login, access control, and auditability at the edge, so Grafana and upstream backends do not each need their own authentication and authorization setup.

It handles browser authentication with OIDC, evaluates authorization from centrally managed identity data, and forwards the headers or tokens each backend expects. In front of Grafana, Prometheus, Loki, OpenSearch, Kibana, VictoriaMetrics, and similar systems, Multipass becomes the single control point for access.

It runs in two modes:

1. **web** for browser-based tools and dashboards.
2. **api** for programmatic systems that expect tokens or trusted headers.

Single sign-on. Namespace isolation. Full audit trail. Zero backend changes.

## Why Multipass?

Observability and operations tools rarely agree on how access should work. One wants OIDC, another expects headers, another wants JWTs. The result is duplicated setup, uneven access control, and too much backend-specific glue.

Multipass solves that at the edge:

- **OIDC SSO** — one browser login flow across the stack
- **OIDC/JWT group authz** — one authorization model driven directly from token claims
- **Two delivery modes** — web for UI-oriented tools, api for systems that expect tokens or headers
- **Backend translation** — tenant headers, JWT passthrough, or trusted web headers depending on what the backend expects
- **Data minimization** — keep identity, authorization, and audit decisions at the edge without pulling more backend data into Multipass than necessary
- **Auditability** — access decisions logged in one place and easy to ship onward

### Supported Applications

- **jwt**: JWT-authenticated systems (LGTM, OpenSearch, Elasticsearch) - see [API.md](doc/API.md)
- **prometheus**: Prometheus-compatible systems (Grafana, Loki, Mimir, Tempo, Thanos, VictoriaMetrics, Cortex, Prometheus, Alertmanager, Jaeger, SigNoz)
- **web**: Header-authenticated web proxy (Grafana, Kibana, OpenSearch, VictoriaMetrics) - see [WEB.md](doc/WEB.md)

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

**Configure backends:**
Edit [k8s/configmap.yaml](k8s/configmap.yaml) with your backend endpoints:

```yaml
backends:
  loki:
    type: prometheus
    endpoint: http://loki.monitoring.svc.cluster.local:3100

  opensearch:
    type: jwt
    endpoint: https://opensearch.logging.svc.cluster.local:9200
```

**Deploy to cluster:**
```bash
kubectl apply -f k8s/
```

**Deploy with in-cluster OIDC provider:**
```bash
kubectl apply -k k8s/oidc/
```

This overlay keeps Multipass on `oidc` and `token` while pointing OIDC at
`oidc-provider.monitoring.svc.cluster.local:8081`.

This creates:
- **ConfigMap**: Backend configuration and OIDC settings
- **Deployment**: 2 replicas with health checks, shared browser sessions, and resource limits
- **Service**: ClusterIP service on port 8080

**Verify:**
```bash
kubectl get pods -n monitoring -l app=multipass
kubectl logs -n monitoring -l app=multipass
```

## Development

See [doc/DEV.md](doc/DEV.md) for local development, testing, build modes, and release instructions.

Use the external OIDC profile when you want Multipass to behave like production integrations.

## License

MIT
