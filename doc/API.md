# API Backend Types and Header Injection

Multipass supports four backend types with different header injection strategies.

## Backend Types

### 1. Prometheus (`type: prometheus`)

**Used for:**
- Loki (logs)
- Grafana (visualization)
- Mimir (metrics)
- Tempo (traces)
- Prometheus
- VictoriaMetrics
- Thanos
- Cortex

**Header injection:**
```
X-Scope-OrgID: <namespace>
```

The namespace is determined from backend configuration when `namespace` is set, otherwise from the request query parameter, and finally defaults to `default`.

**Example config:**
```yaml
backends:
  loki:
    type: prometheus
    endpoint: http://loki:3100
    # namespace: monitoring
  
  prometheus:
    type: prometheus
    endpoint: http://prometheus:9090
```

**How it works:**
1. User authenticated → JWT validated → UserInfo extracted
2. Authz check → User's allowed namespaces determined
3. Namespace resolved from fixed backend config, request query param, or `default`
4. **X-Scope-OrgID header injected** with namespace value
5. Backend enforces multi-tenancy using this header

**Query example:**
```bash
curl -H "Authorization: Bearer <jwt>" \
  http://multipass:8080/loki/api/v1/query?namespace=prod
  
# Multipass injects: X-Scope-OrgID: prod
# Loki receives: /api/v1/query with X-Scope-OrgID header
```

### 2. OpenSearch / Elasticsearch backends (`type: jwt`)

**Used for:**
- OpenSearch
- Elasticsearch

**Header injection:**
```
Authorization: Bearer <jwt>
```

The original user JWT is passed through to the backend for native RBAC.

**Example config:**
```yaml
backends:
  opensearch:
    type: jwt
    endpoint: http://opensearch:9200
```

**How it works:**
1. User authenticated → JWT validated → UserInfo extracted
2. Authz check in Multipass (optional, can rely on OpenSearch RBAC)
3. **Original JWT passed through** in Authorization header
4. OpenSearch validates JWT and enforces its own RBAC

**Query example:**
```bash
curl -H "Authorization: Bearer <jwt>" \
  http://multipass:8080/opensearch/_search
  
# Multipass passes through: Authorization: Bearer <jwt>
# OpenSearch receives: /_search with original JWT
# OpenSearch enforces RBAC based on JWT claims
```

**Note:** OpenSearch has native JWT/OIDC support and can validate tokens and enforce permissions independently. Multipass does not mint a new JWT or add backend-specific role claims for OpenSearch. For `type: jwt`, Multipass forwards the original bearer token unchanged.

### 3. Generic (`type: generic`)

**Used for:**
- Jaeger
- Zipkin
- Custom backends
- Any backend that doesn't need special headers

**Header injection:**
Only static headers from config, no dynamic injection.

**Example config:**
```yaml
backends:
  jaeger:
    type: generic
    endpoint: http://jaeger:16686
    headers:
      X-Custom-Header: "static-value"
```

**How it works:**
1. User authenticated → JWT validated
2. Authz check (optional)
3. Only static headers from config are added
4. No namespace or JWT injection

**Query example:**
```bash
curl -H "Authorization: Bearer <jwt>" \
  http://multipass:8080/jaeger/api/traces/abc123
  
# Multipass only adds static headers from config
# Jaeger receives: /api/traces/abc123
```

### 4. Web (`type: web`)

**Used for:**
- Grafana (web UI with auth.proxy mode)
- Kibana (web UI with reverse proxy auth)
- OpenSearch Dashboards (web UI with proxy auth)
- VictoriaMetrics UI (vmui)
- Any web dashboard that supports header-based authentication

**Header injection:**
```
X-WEBAUTH-USER: <user_id>          (configurable header name)
X-WEBAUTH-EMAIL: <user_email>      (optional)
X-WEBAUTH-NAME: <user_name>        (optional)
X-WEBAUTH-GROUP: <groups>          (optional, comma-separated)
```

Headers are configured per backend in the `webConfig` section.

**Example config:**
```yaml
backends:
  grafana-web:
    type: web
    endpoint: http://grafana:3000
    webConfig:
      userHeader: X-WEBAUTH-USER    # Required: user ID
      emailHeader: X-WEBAUTH-EMAIL  # Optional: user email
      nameHeader: X-WEBAUTH-NAME    # Optional: display name
      groupsHeader: X-WEBAUTH-GROUP # Optional: groups (requires authz.enabled=true)
```

**How it works:**
1. User authenticated → JWT validated → UserInfo extracted with email/name
2. Authz check (if enabled) → User's groups resolved from token claims and group mappings
3. **User identity headers injected** based on webConfig
4. **Groups header injected** (comma-separated) if authz enabled and configured
5. Web dashboard trusts headers for SSO (must be behind network policy)

**Query example:**
```bash
curl -H "Authorization: Bearer <jwt>" \
  http://multipass:8080/grafana-web/api/dashboards
  
# Multipass injects: 
#   X-WEBAUTH-USER: user123
#   X-WEBAUTH-EMAIL: user@example.com
#   X-WEBAUTH-NAME: John Doe
#   X-WEBAUTH-GROUP: team-platform,team-sre,admins
# Grafana receives: /api/dashboards with identity headers
```

**Dashboard configuration examples:**

Grafana with auth.proxy:
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

**Security note:** Web backends must trust the injected headers. Deploy behind Kubernetes NetworkPolicy or similar to prevent header forgery.

**See also:** [WEB.md](WEB.md) for detailed setup instructions.

## Header Injection Flow

```
1. Request arrives: GET /loki/api/v1/query?namespace=prod
                   Authorization: Bearer <jwt>

2. Auth middleware:
   - Validates JWT
   - Extracts UserInfo
   - Stores JWT in context

3. Authz check (if enabled):
   - Evaluates user's allowed namespaces
   - Checks if 'prod' is allowed
   - Returns 403 if denied

4. Namespace stored in context

5. Proxy Director (backend-specific):
   - Type: prometheus → Inject X-Scope-OrgID: prod
   - Type: jwt → Inject Authorization: Bearer <jwt>
   - Type: web → Inject user identity headers (X-WEBAUTH-USER, etc.)
   - Type: generic → Only static headers

6. Request proxied to backend with injected headers
```

## Configuration Examples

### Full Prometheus Stack
```yaml
backends:
  loki:
    type: prometheus
    endpoint: http://loki:3100
  
  mimir:
    type: prometheus
    endpoint: http://mimir:8080
  
  tempo:
    type: prometheus
    endpoint: http://tempo:3100
  
  grafana:
    type: prometheus
    endpoint: http://grafana:3000
```

### OpenSearch with JWT Passthrough
```yaml
backends:
  opensearch:
    type: jwt
    endpoint: https://opensearch:9200
    headers:
      # Static header for all requests
      X-Custom-Tenant: "production"
```

### Mixed Environment
```yaml
backends:
  # Prometheus backends with X-Scope-OrgID
  loki:
    type: prometheus
    endpoint: http://loki:3100
  
  # OpenSearch with JWT passthrough
  opensearch:
    type: jwt
    endpoint: http://opensearch:9200
  
  # Web dashboard with header-based auth
  grafana-web:
    type: web
    endpoint: http://grafana:3000
    webConfig:
      userHeader: X-WEBAUTH-USER
      emailHeader: X-WEBAUTH-EMAIL
      groupsHeader: X-WEBAUTH-GROUP
  
  # Generic backend with static headers only
  custom-api:
    type: generic
    endpoint: http://custom-api:8080
    headers:
      X-API-Key: "secret"
```

## Static vs Dynamic Headers

**Static headers (from config):**
- Set once at startup
- Same for all requests
- Useful for API keys, tenant IDs, etc.

**Dynamic headers (injected per request):**
- `X-Scope-OrgID`: Based on user's authorized namespace (prometheus backends)
- `Authorization`: User's JWT for passthrough (jwt backends)
- `X-WEBAUTH-*`: User identity and groups (web backends)

**Both can coexist:**
```yaml
backends:
  loki:
    type: prometheus
    endpoint: http://loki:3100
    headers:
      X-Static-Tenant: "company-a"  # Static
      # X-Scope-OrgID added dynamically per request
```

## Namespace Extraction

Namespace currently comes from:

1. **Fixed backend namespace:**
  ```yaml
  backends:
    mimir:
     type: prometheus
     endpoint: http://mimir:8080
     namespace: monitoring
  ```
  When set, this takes precedence and caller-supplied `?namespace=` values are ignored.

2. **Query parameter:**
   ```
   /loki/api/v1/query?namespace=prod
   ```

3. **Default** (if not specified):
   ```
   Uses "default" namespace
   ```

Path-based namespace extraction is not currently implemented.

## Security Considerations

### Prometheus Backends
- Multipass controls namespace via X-Scope-OrgID
- Backend trusts this header (must be behind network policy)
- User cannot forge namespace (Multipass validates authz first)

### OpenSearch Backends
- Backend validates JWT independently
- Multipass authz check optional (can rely on OpenSearch RBAC)
- JWT signature verified by OpenSearch
- Multipass does not project namespaces or temporary elevated roles into OpenSearch-native roles
- Best fit is edge gating in Multipass plus backend-native JWT RBAC where needed

### Generic Backends
- No special security enforcement
- Backend must implement its own auth
- Multipass only provides authenticated user identity

### Web Backends
- Backend trusts injected identity headers (similar to Prometheus backends)
- **Must be behind network policy** to prevent header forgery
- Groups integrated from authz for RBAC in dashboards
- SSO experience without OIDC configuration in each dashboard

## Troubleshooting

**Prometheus backend returns 401:**
- Check if X-Scope-OrgID header is being injected
- Verify backend trusts Multipass (no signature verification)

**OpenSearch backend returns 403:**
- Check if JWT is being passed through
- Verify OpenSearch JWT validation config
- Check OpenSearch role mappings

**Backend receives wrong namespace:**
- Check authz group mappings
- Verify the client is sending `?namespace=...`
- Check audit logs for actual namespace used

**Web backend not recognizing user:**
- Check if identity headers are being injected
- Verify header names match dashboard configuration
- Check dashboard logs for header values received
- Ensure webConfig is properly configured

**Groups not appearing in web dashboard:**
- Verify `authz.enabled=true` in Multipass config
- Check that the validated token contains the expected `groups` claim values
- Ensure `groupsHeader` is configured in webConfig
- Verify dashboard is configured to read groups from header

## Testing

### Test Prometheus Header Injection
```bash
# With curl
curl -H "Authorization: Bearer <jwt>" \
  "http://multipass:8080/loki/api/v1/query?namespace=dev"

# Check backend receives X-Scope-OrgID: dev
```

### Test OpenSearch Passthrough
```bash
curl -H "Authorization: Bearer <jwt>" \
  "http://multipass:8080/opensearch/_search"

# Check backend receives Authorization: Bearer <jwt>
```

### Test Web Backend Headers
```bash
curl -H "Authorization: Bearer <jwt>" \
  "http://multipass:8080/grafana-web/api/dashboards"

# Check backend receives:
#   X-WEBAUTH-USER: user123
#   X-WEBAUTH-EMAIL: user@example.com
#   X-WEBAUTH-GROUP: team-platform,team-sre
```

### Test with tcpdump
```bash
# On backend node
sudo tcpdump -i any -A -s 0 'tcp port 3100 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Look for X-Scope-OrgID or Authorization headers
```

