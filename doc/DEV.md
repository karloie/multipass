# Development

Use [config.oidc.yaml](../config.oidc.yaml) for the default realistic local profile.

## Local Run

Preferred local flow:

```bash
cp config.oidc.yaml config.yaml
MULTIPASS_LOG_LEVEL=debug MULTIPASS_LOG_FORMAT=text go run ./cmd/multipass config.yaml
```

This keeps Multipass on the same `oidc` and `token` providers used in normal operation.

## Test

```bash
make test
make coverage
make ci-build
make ci-test
make ci-integration-test
```

## Logging

- `MULTIPASS_LOG_LEVEL`: `debug`, `info`, `warn`, `error`
- `MULTIPASS_LOG_FORMAT`: `json`, `text`

## Docker

```bash
docker build -t multipass:latest .
docker run -p 8080:8080 -v ./config.yaml:/etc/multipass/config.yaml multipass:latest /etc/multipass/config.yaml
make docker-release TAG=v0.0.1
```

Prebuilt images are published as `karloie/multipass`.

## Release

Shipkit handles releases from GitHub Actions.

- normal path: push to `main` with release markers
- manual path: `workflow_dispatch` with `patch`, `minor`, or `major`

Local dry run:

```bash
make -n ci-release
```