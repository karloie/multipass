.PHONY: build build-prod run test integration-test coverage clean docker-build docker-run docker-login
.PHONY: ci-generate ci-build ci-test ci-integration-test ci-release ci-summary

# Build variables
BINARY_NAME=multipass
VERSION?=v0.0.1
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DOCKER_IMAGE?=karloie/multipass
DEV_TAG?=dev
DOCKER_PLATFORMS?=linux/amd64,linux/arm64
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)"

build: build-prod

build-prod:
	@echo "Building PRODUCTION binary"
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/multipass
	@echo "✓ Production build complete: ./$(BINARY_NAME)"

run:
	@echo "Starting Multipass"
	@echo "Preferred realistic local flow: run a local OIDC provider and start Multipass with -config config.oidc.yaml"
	@echo "Optional: set MULTIPASS_LOG_LEVEL=debug|info|warn|error"
	@echo "Optional: set MULTIPASS_LOG_FORMAT=json|text"
	go run $(LDFLAGS) ./cmd/multipass

test:
	go test -count=1 -v -tags test ./...

integration-test:
	go test -count=1 -v -tags integration ./...

coverage:
	@go test -count=1 -tags test -coverprofile=coverage.out ./... > /dev/null 2>&1
	@printf "  %-38s │ %9s │ %10s  \n" "Package" "Coverage" "Cross Cov"
	@echo "╔──────────────────────────────────────────────────────────────────╗"
	@for pkg in $$(go list ./...); do \
		shortpkg=$$(echo $$pkg | sed 's|github.com/[^/]*/[^/]*/||'); \
		owncov=$$(go test -tags test -cover $$pkg 2>&1 | grep -oP 'coverage: \K[0-9.]+%' | head -1); \
		if [ -z "$$owncov" ]; then owncov="n/a"; fi; \
		pkgfile=$$(echo $$shortpkg | sed 's|/|-|g'); \
		go test -tags test -coverprofile=cross-$$pkgfile.out -coverpkg=$$pkg ./... > /dev/null 2>&1 || continue; \
		if [ -f cross-$$pkgfile.out ] && [ -s cross-$$pkgfile.out ]; then \
			crosscov=$$(go tool cover -func=cross-$$pkgfile.out 2>/dev/null | grep "^$$pkg/" | awk '{sum+=substr($$NF,1,length($$NF)-1); cnt++} END {if (cnt>0) printf "%.1f%%", sum/cnt; else print "0.0%"}'); \
			if [ -z "$$crosscov" ]; then crosscov="0.0%"; fi; \
		else \
			crosscov="n/a"; \
		fi; \
		printf "║ %-38s │ %9s │ %11s ║\n" "$$shortpkg" "$$owncov" "$$crosscov"; \
	done
	@echo "╚──────────────────────────────────────────────────────────────────╝"
	@printf "  %-38s │ %9s │ %11s  \n" "TOTAL" "$$(go tool cover -func=coverage.out 2>/dev/null | grep 'total:' | awk '{print $$3}')" ""
	@rm -f cross-*.out coverage.out

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-test $(BINARY_NAME)-prod
	rm -f *.out

docker-build:
	docker build -t $(BINARY_NAME):$(VERSION) .

docker-login:
	@if [ -n "$(DOCKERHUB_USERNAME)" ] && [ -n "$(DOCKERHUB_TOKEN)" ]; then \
		echo "Logging into Docker Hub as $(DOCKERHUB_USERNAME)"; \
		echo "$(DOCKERHUB_TOKEN)" | docker login -u "$(DOCKERHUB_USERNAME)" --password-stdin; \
	else \
		echo "DOCKERHUB_USERNAME/DOCKERHUB_TOKEN not set, using existing docker credentials"; \
	fi

docker-run:
	docker run -p 8080:8080 -v $(PWD)/config.yaml:/etc/multipass/config.yaml $(BINARY_NAME):$(VERSION)

# Development helpers
fmt:
	go fmt ./...

lint:
	golangci-lint run

deps:
	go mod download
	go mod tidy

# Quick test with curl
smoke-test:
	@echo "Testing health endpoint..."
	@curl -s http://localhost:8080/health
	@echo "\n\nTesting info endpoint..."
	@curl -s http://localhost:8080/

# Shipkit CI hooks
ci-generate:
	@echo "No code generation needed for multipass"

ci-build: build-prod
ci-test: test
ci-integration-test: integration-test

ci-release:
	@echo "Building Multipass release artifacts"
	shipkit install --force goreleaser
	shipkit publish-goreleaser --skip-docker --clean
	shipkit publish-docker

ci-summary:
	@echo "Multipass release complete"
