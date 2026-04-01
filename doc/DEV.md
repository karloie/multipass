# Development Guide

## Local Development

**Quick start with an external OIDC provider:**
```bash
cp config.oidc.yaml config.yaml

# Terminal 1
# Start your local OIDC provider on http://localhost:8081

# Terminal 2
cd ../multipass
MULTIPASS_LOG_LEVEL=debug MULTIPASS_LOG_FORMAT=text go run ./cmd/multipass -config config.yaml
```

This is the preferred realistic local flow because Multipass stays on the same
`oidc` and `token` providers it uses in normal operation.

Log output defaults to structured JSON. `MULTIPASS_LOG_LEVEL` controls verbosity and `MULTIPASS_LOG_FORMAT` can switch output to `text` for local readability. Default level is `info`.

### OIDC Profile

If you want Multipass to behave like it is talking to external identity systems,
run a local OIDC provider and point Multipass at it with the standard providers:

```yaml
auth:
  provider: oidc
  oidc:
    providerName: forgerock
    issuerUrl: http://oidc-provider.monitoring.svc.cluster.local:8081
    clientId: multipass
    clientSecret: ignored-by-local-oidc
    redirectUrl: http://multipass:8080/login/generic_oauth

authz:
  enabled: true
  provider: token
```

To switch to real OIDC, keep `provider: oidc` and `provider: token`
and change the issuer and client settings.

The repo includes [config.oidc.yaml](config.oidc.yaml) as a ready-to-run local profile.

For cluster testing, there is also a Kustomize overlay at [k8s/oidc/kustomization.yaml](k8s/oidc/kustomization.yaml)
which rewrites the Multipass ConfigMap to point at an in-cluster OIDC service.

**Health check:**
```bash
curl http://localhost:8080/health
```

## Testing

**Run all tests:**
```bash
make test
```

**Coverage report:**
```bash
make coverage
```

Shows per-package coverage and cross-package integration coverage in a formatted table.

## CI Pipeline

The same steps that run in CI can be executed locally:

```bash
make ci-build           # Build production binary
make ci-test            # Run all tests
make ci-integration-test # Run integration tests
```

These targets are used by GitHub Actions and follow [shipkit](https://github.com/karloie/shipkit) conventions. Other shipkit hooks (ci-generate, ci-release) are not implemented and will be skipped.

## Build Modes

- **Production** (`make build`): OIDC authentication with token-based authz and memory audit storage
- **Test** (`make test`): Unit tests with local fakes and test doubles

Supported log levels for `MULTIPASS_LOG_LEVEL`: `debug`, `info`, `warn`, `error`.
Supported log formats for `MULTIPASS_LOG_FORMAT`: `json`, `text`.

## Docker

**Docker Hub:**

Pre-built images are available on Docker Hub:
```bash
docker pull karloie/multipass:latest
docker pull karloie/multipass:v0.0.1  # Specific version
```

**Build locally:**
```bash
docker build -t multipass:latest .
```

**Run:**
```bash
docker run -p 8080:8080 -v ./config.yaml:/etc/multipass/config.yaml karloie/multipass:latest
```

Note: Docker builds use the same runtime feature set as the normal binary.

## Releases

New releases are handled by Shipkit from GitHub Actions.

Two entry points exist:

- push to `main` with release markers so Shipkit plans and publishes the next tag
- manual `workflow_dispatch` on the release workflow with `patch`, `minor`, or `major`

The publish step performs only:

- Go binary release artifacts through GoReleaser
- Docker image publish to Docker Hub

There is also a manual `re-release` workflow for republishing the latest tag.

If you want to inspect the local publish contract without publishing:

```bash
make -n ci-release
```

Shipkit publishes:
- Docker image build for `linux/amd64` and `linux/arm64`
- Push to Docker Hub as `karloie/multipass:v0.0.1` and `karloie/multipass:latest`
- GitHub Release with binaries for Linux, macOS (amd64 and arm64)
