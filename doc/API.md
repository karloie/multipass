# API Backends

Use [config.example.yaml](../config.example.yaml) as the full source of config examples.

## Types

- `prometheus`: injects `X-Scope-OrgID`; use for tenant-aware multi-tenant APIs such as Loki, Mimir, Tempo, Prometheus, Thanos, Cortex, and VictoriaMetrics
- `jwt`: forwards the original `Authorization: Bearer <jwt>`; use when the backend already enforces its own RBAC
- `generic`: plain reverse proxy with optional static headers
- `web`: forwards trusted identity headers for browser UIs

## Prometheus Extras

- Namespace comes from `backend.namespace`, request routing, or `default`
- `namespaceRouting.source` supports `query`, `body`, or `both`
- `queryRewrite.tenantLabel` is the shortest way to enforce tenant matchers on Prometheus-style APIs
- `queryRewrite.semantics` supports `promql` and `selector`
- `logql` is intentionally unsupported because the obvious parser path brings in AGPL-licensed code, which does not fit this repository's license posture

Minimal request-routed example:

```yaml
backends:
  mimir-shared:
    type: prometheus
    endpoint: http://mimir:8080
    namespaceRouting:
      mode: request
      parameter: tm_tenant
    queryRewrite:
      tenantLabel:
        name: namespace
        value: "{{namespace}}"
```

## Query Rewrite

`queryRewrite.operations` mutates outbound query parameters.

Actions: `add`, `set`, `delete`, `rename`

Templates: `{{backend}}`, `{{namespace}}`, `{{host}}`, `{{route}}`, `{{method}}`

Rewrite runs after request-mode namespace routing strips its routing parameter and before backend proxying.

## Web Backends

Use `type: web` when the backend trusts identity headers from Multipass.

Minimal config:

```yaml
backends:
  grafana-web:
    type: web
    endpoint: http://grafana:3000
    webConfig:
      userHeader: X-WEBAUTH-USER
      emailHeader: X-WEBAUTH-EMAIL
      groupsHeader: X-WEBAUTH-GROUP
```

Available `webConfig` fields:

- `userHeader`
- `emailHeader`
- `nameHeader`
- `groupsHeader`
- `roleHeader`
- `roleMappings`

When `authz.enabled=true`, Multipass forwards evaluated groups. Otherwise it falls back to token groups when present.

Example backend-side settings:

Grafana:

```ini
[auth.proxy]
enabled = true
header_name = X-WEBAUTH-USER
header_property = username
auto_sign_up = true
headers = Groups:X-WEBAUTH-GROUP
```

OpenSearch Dashboards:

```yaml
opensearch_security.auth.type: "proxy"
opensearch_security.auth.proxy.header: "X-WEBAUTH-USER"
opensearch_security.auth.proxy.roles_header: "X-WEBAUTH-GROUP"
```

Rules:

- do not expose the dashboard directly; it must only be reachable through Multipass
- treat forwarded headers as trusted only from Multipass
- use backend-native RBAC if you need more than edge identity propagation
- use `type: prometheus` for tenant-aware data-plane enforcement; `type: web` is mainly for browser SSO

Quick debug backend:

```yaml
backends:
  echo-web:
    type: web
    endpoint: http://httpbin:80/headers
    webConfig:
      userHeader: X-User
```