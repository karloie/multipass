# Web Backend Configuration

Multipass can act as a reverse proxy for web dashboards (Grafana, Kibana, etc.), providing **Single Sign-On** through header-based authentication. This eliminates the need to configure OIDC separately in each dashboard.

## Benefits

- **Single Sign-On**: Users authenticate once to Multipass, access all dashboards without separate logins
- **Simplified Deployment**: No OIDC configuration needed in each tool
- **Consistent Edge Authentication**: One login path for both web interfaces and APIs
- **Unified Audit Trail**: All access (web + API) logged in one place
- **Group/Role Management**: Automatically inject evaluated user groups for RBAC in dashboards

## Configuration

### Multipass Configuration

Add a `web` backend type with `webConfig` specifying which headers to inject:

```yaml
backends:
  grafana-web:
    type: web
    endpoint: http://grafana.monitoring.svc.cluster.local:3000
    webConfig:
      userHeader: X-WEBAUTH-USER    # Required: user ID/username
      emailHeader: X-WEBAUTH-EMAIL  # Optional: user email
      nameHeader: X-WEBAUTH-NAME    # Optional: display name
      groupsHeader: X-WEBAUTH-GROUP # Optional: comma-separated groups (authz groups or JWT groups)
      roleHeader: X-WEBAUTH-ROLE    # Optional: backend-native role header
      roleMappings:
        App-Grafana-Admins: GrafanaAdmin
        App-Grafana-Editors: Editor
```

**Groups Integration:**
When `authz.enabled=true`, Multipass injects groups from the evaluated authorization result. With `authz.provider: token`, those groups come directly from the validated JWT/ID token. When authz is disabled, Multipass falls back to `groups` claims already present in the validated token. This enables role mapping in dashboards without requiring a second directory lookup.

With `authz.provider: token`, Multipass evaluates namespace access directly from the validated token's `groups` claim. That is the intended fit when your OIDC token already contains the tenant-granting groups.

For backends that support a native role header, Multipass can also derive that role from incoming groups with `roleHeader` plus `roleMappings`.

## Grafana Setup

Grafana supports reverse proxy authentication via `auth.proxy` mode.

### 1. Configure Grafana

Edit `grafana.ini` or set environment variables:

```ini
[auth.proxy]
enabled = true
header_name = X-WEBAUTH-USER
header_property = username
auto_sign_up = true
enable_login_token = false

[users]
allow_sign_up = false
auto_assign_org = true
auto_assign_org_role = Viewer
```

Environment variables:
```bash
GF_AUTH_PROXY_ENABLED=true
GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER
GF_AUTH_PROXY_HEADER_PROPERTY=username
GF_AUTH_PROXY_AUTO_SIGN_UP=true
```

### 2. Configure Multipass

```yaml
backends:
  grafana-web:
    type: web
    endpoint: http://grafana:3000
    webConfig:
      userHeader: X-WEBAUTH-USER
      emailHeader: X-WEBAUTH-EMAIL
      groupsHeader: X-WEBAUTH-GROUP
      roleHeader: X-WEBAUTH-ROLE
      roleMappings:
        App-Grafana-Admins: GrafanaAdmin
        App-Grafana-Editors: Editor
```

**Optional authorization in Multipass:**
```yaml
authz:
  enabled: true
  provider: token
  groupMappings:
    team-platform: [dev, test, prod]
    team-sre: [prod]
```

### 3. Map Roles to Grafana (Optional)

Grafana auth proxy can read a role header directly. This is simpler than relying on separate Grafana-side RBAC mapping when your IdP already emits the relevant groups.

Add to `grafana.ini`:
```ini
[auth.proxy]
headers = Name:X-WEBAUTH-NAME Email:X-WEBAUTH-EMAIL Groups:X-WEBAUTH-GROUP Role:X-WEBAUTH-ROLE
```

### 4. Access Grafana

Navigate to: `http://multipass:8080/grafana-web/`

Users will be automatically logged in with their Multipass identity.

### 5. Provision Datasources Through Multipass

If Multipass is the authority for Loki, Mimir, or Tempo access, Grafana datasource URLs must point to Multipass, not directly to the backend services.

Example rollout for three namespaces:

```yaml
datasources:
  - name: Loki UTV
    type: loki
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/loki-utv

  - name: Loki Monitoring
    type: loki
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/loki-monitoring

  - name: Loki Applikasjonsplattform
    type: loki
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/loki-applikasjonsplattform

  - name: Mimir UTV
    type: prometheus
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/mimir-utv

  - name: Mimir Monitoring
    type: prometheus
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/mimir-monitoring

  - name: Mimir Applikasjonsplattform
    type: prometheus
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/mimir-applikasjonsplattform

  - name: Tempo UTV
    type: tempo
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/tempo-utv

  - name: Tempo Monitoring
    type: tempo
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/tempo-monitoring

  - name: Tempo Applikasjonsplattform
    type: tempo
    access: proxy
    url: http://multipass.monitoring.svc.cluster.local:8080/tempo-applikasjonsplattform
```

For this pattern to hold, each Multipass alias should be configured with a fixed `namespace`, and direct user access to Loki, Mimir, and Tempo should be blocked. Users may still see multiple datasources in Grafana, but Multipass remains the control point for which namespace each datasource can read.

## Kibana Setup

Kibana can use anonymous authentication with request header extraction. This setup commonly sits in front of an Elasticsearch backend.

### 1. Configure Elasticsearch for Kibana

Enable anonymous access with a restricted role:

```yaml
xpack.security.authc.anonymous:
  username: anonymous
  roles: kibana_viewer
  authz_exception: false
```

### 2. Configure Kibana

Use a custom plugin or proxy to extract user identity from headers. Alternatively, use OpenSearch which has better reverse proxy support.

### 3. Configure Multipass

```yaml
backends:
  kibana-web:
    type: web
    endpoint: http://kibana:5601
    webConfig:
      userHeader: X-Proxy-User
      emailHeader: X-Proxy-Email
```

This is still a `type: web` Multipass backend in Multipass. Elasticsearch is the supported backing product for Kibana here, but not a separate Multipass backend type.

## OpenSearch Dashboards Setup

OpenSearch Dashboards has built-in support for proxy authentication.

### 1. Configure OpenSearch Security

```yaml
# opensearch.yml
opensearch_security.auth.type: "proxy"
opensearch_security.auth.proxy.header: "X-Authenticated-User"
opensearch_security.auth.proxy.roles_header: "X-Authenticated-Roles"
```

### 2. Configure Multipass

```yaml
backends:
  opensearch-web:
    type: web
    endpoint: http://opensearch-dashboards:5601
    webConfig:
      userHeader: X-Authenticated-User
      emailHeader: X-Authenticated-Email
      groupsHeader: X-Authenticated-Roles  # OpenSearch calls them "roles"
```

**Enable authorization:**
```yaml
authz:
  enabled: true
  provider: token
  groupMappings:
    logs-team: [logs, metrics]
    admin-team: ["*"]
```

OpenSearch will receive groups as `X-Authenticated-Roles: logs-team,admin-team` and map them to internal OpenSearch roles.

This is group forwarding, not elevated-role forwarding. If you need OpenSearch-native roles derived from temporary elevated access, that requires explicit backend-specific projection logic beyond the current `web` backend behavior.

## VictoriaMetrics Setup

VictoriaMetrics UI (vmui) can display user information when proxied.

### 1. Configure Multipass

```yaml
backends:
  victoriametrics-web:
    type: web
    endpoint: http://victoriametrics:8428
    webConfig:
      userHeader: X-Scope-User
```

### 2. Access VictoriaMetrics UI

Navigate to: `http://multipass:8080/victoriametrics-web/vmui`

The vmui interface will display the user context from the `X-Scope-User` header.

**Note**: VictoriaMetrics primarily uses this for display/auditing. For multi-tenancy in the data plane, use the `prometheus` backend type which injects `X-Scope-OrgID` for API queries.

## Custom Dashboards

Any web application that supports header-based authentication can be proxied through Multipass:

```yaml
backends:
  custom-dashboard:
    type: web
    endpoint: http://my-app:8080
    webConfig:
      userHeader: X-Remote-User
      emailHeader: X-Remote-Email
      nameHeader: X-Remote-Name
```

Your application reads these headers to identify the authenticated user.

## Security Considerations

### 1. Block Direct Access

**CRITICAL**: Ensure backend dashboards are **only accessible through Multipass**. If users can access Grafana/Kibana directly, they can forge headers.

### 2. Know the Scope of Enforcement

- `web` backends are best for SSO, identity propagation, and coarse access checks at the edge
- Grafana and OpenSearch Dashboards requests are not namespace-shaped in the same way as Loki or Mimir API traffic
- If you need backend-native authorization semantics, configure them in the backend using the forwarded identity or groups
- If you need namespace-aware enforcement, `prometheus` backends are the strongest fit because Multipass injects `X-Scope-OrgID`

#### Kubernetes Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: grafana-ingress
spec:
  podSelector:
    matchLabels:
      app: grafana
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: multipass
    ports:
    - protocol: TCP
      port: 3000
```

#### Service Mesh (Istio)

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: grafana-allow-multipass
spec:
  selector:
    matchLabels:
      app: grafana
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/monitoring/sa/multipass"]
```

### 2. Header Validation

Backend applications should:
- **Never trust headers blindly** - only when traffic comes through Multipass
- Validate header format and content
- Log authentication events

### 3. TLS Configuration

Use TLS between Multipass and backend services in production:

```yaml
backends:
  grafana-web:
    type: web
    endpoint: https://grafana.monitoring.svc.cluster.local:3000
```

## Troubleshooting

### Users Not Authenticated

1. **Check headers are reaching backend**:
   ```bash
   # Inside Grafana pod
   curl -H "X-WEBAUTH-USER: testuser" http://localhost:3000/api/user
   ```

2. **Verify Grafana auth.proxy is enabled**:
   ```bash
   grep auth.proxy /etc/grafana/grafana.ini
   ```

3. **Check Multipass audit logs**:
   ```sql
  Filter Multipass logs for audit entries for the relevant backend and user.
   ```

### Access Denied Errors

1. **Verify user is authenticated to Multipass**:
   - Check session cookie is present
   - Try logging out and back in

2. **Check authorization is disabled for web backends** (unless you want namespace restrictions):
   ```yaml
   authz:
     enabled: false  # web backends typically don't need namespace restrictions
   ```

### Missing User Information

If Email or Name fields are empty:

1. **Check IDP returns these claims**:
  - Ensure `email` and `name` scopes are requested by your OIDC provider
  - Configure user attribute mapping in your IdP when those claims are not emitted by default

2. **Verify the token actually contains those claims** before debugging downstream header injection

## Testing

### Local Development with external OIDC

```bash
# Start your local OIDC provider on http://localhost:8081

# Start Multipass with the checked-in OIDC profile
cd ../multipass
go run ./cmd/multipass config.oidc.yaml

# Login through the normal OIDC route
xdg-open "http://localhost:8080/login"

# Access Grafana through Multipass
curl -c cookies.txt -b cookies.txt http://localhost:8080/grafana-web/api/user
```

### Verify Headers

Run a test backend that echoes headers:

```yaml
backends:
  echo-web:
    type: web
    endpoint: http://httpbin:80/headers
    webConfig:
      userHeader: X-User
```

Access `http://multipass:8080/echo-web/` to see injected headers.

## References

- [Grafana Auth Proxy Documentation](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/auth-proxy/)
- [OpenSearch Security Proxy Authentication](https://opensearch.org/docs/latest/security/authentication-backends/proxy/)
- [Kibana Security Configuration](https://www.elastic.co/guide/en/kibana/current/security-settings-kb.html)
- [VictoriaMetrics Multi-tenancy](https://docs.victoriametrics.com/#multitenancy)
