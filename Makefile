.PHONY: build run test integration-test coverage clean docker-login docker-build docker-publish docker-upload-readme docker-release
.PHONY: ci-generate ci-build ci-test ci-integration-test ci-release ci-summary

.DEFAULT_GOAL := test

GO ?= go
SHIPKIT ?= shipkit

BINARY_NAME ?= multipass
CMD_PACKAGE ?= ./cmd/multipass
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DOCKER_IMAGE ?= karloie/multipass
DOCKER_BUILD_PLATFORMS ?= linux/amd64
DOCKER_PUBLISH_PLATFORMS ?= linux/amd64
CONFIG ?=

GO_TEST_FLAGS ?= -count=1 -v
LDFLAGS = -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)"

build:
	$(GO) build $(LDFLAGS) -o $(BINARY_NAME) $(CMD_PACKAGE)

test:
	$(GO) test $(GO_TEST_FLAGS) -tags test ./...

integration-test:
	$(GO) test $(GO_TEST_FLAGS) -tags integration ./...

coverage:
	@$(GO) test -count=1 -tags test -coverprofile=coverage.out ./... > /dev/null 2>&1
	@printf "  %-38s │ %9s │ %10s  \n" "Package" "Coverage" "Cross Cov"
	@echo "╔──────────────────────────────────────────────────────────────────╗"
	@for pkg in $$($(GO) list ./...); do \
		shortpkg=$$(echo $$pkg | sed 's|github.com/[^/]*/[^/]*/||'); \
		owncov=$$($(GO) test -tags test -cover $$pkg 2>&1 | grep -oP 'coverage: \K[0-9.]+%' | head -1); \
		if [ -z "$$owncov" ]; then owncov="n/a"; fi; \
		pkgfile=$$(echo $$shortpkg | sed 's|/|-|g'); \
		$(GO) test -tags test -coverprofile=cross-$$pkgfile.out -coverpkg=$$pkg ./... > /dev/null 2>&1 || continue; \
		if [ -f cross-$$pkgfile.out ] && [ -s cross-$$pkgfile.out ]; then \
			crosscov=$$($(GO) tool cover -func=cross-$$pkgfile.out 2>/dev/null | grep "^$$pkg/" | awk '{sum+=substr($$NF,1,length($$NF)-1); cnt++} END {if (cnt>0) printf "%.1f%%", sum/cnt; else print "0.0%"}'); \
			if [ -z "$$crosscov" ]; then crosscov="0.0%"; fi; \
		else \
			crosscov="n/a"; \
		fi; \
		printf "║ %-38s │ %9s │ %11s ║\n" "$$shortpkg" "$$owncov" "$$crosscov"; \
	done
	@echo "╚──────────────────────────────────────────────────────────────────╝"
	@printf "  %-38s │ %9s │ %11s  \n" "TOTAL" "$$($(GO) tool cover -func=coverage.out 2>/dev/null | grep 'total:' | awk '{print $$3}')" ""
	@rm -f cross-*.out coverage.out

run:
	@test -n "$(CONFIG)" || (echo "Usage: make run CONFIG=config.oidc.yaml" && exit 1)
	$(GO) run $(LDFLAGS) $(CMD_PACKAGE) $(CONFIG)

clean:
	rm -f $(BINARY_NAME)
	rm -f *.out

docker-login:
	@if [ -n "$(DOCKERHUB_USERNAME)" ] && [ -n "$(DOCKERHUB_TOKEN)" ]; then \
		echo "Logging into Docker Hub as $(DOCKERHUB_USERNAME)"; \
		echo "$(DOCKERHUB_TOKEN)" | docker login -u "$(DOCKERHUB_USERNAME)" --password-stdin; \
	else \
		echo "DOCKERHUB_USERNAME/DOCKERHUB_TOKEN not set, using existing docker credentials"; \
	fi

docker-build:
	@test -n "$(TAG)" || (echo "Usage: make docker-build TAG=v0.0.1" && exit 1)
	$(SHIPKIT) release-docker --image "$(DOCKER_IMAGE)" --tag "$(TAG)" --platform "$(DOCKER_BUILD_PLATFORMS)" --push=false --update-readme=false

docker-publish: docker-login
	@test -n "$(TAG)" || (echo "Usage: make docker-publish TAG=v0.0.1" && exit 1)
	$(SHIPKIT) release-docker --image "$(DOCKER_IMAGE)" --tag "$(TAG)" --platform "$(DOCKER_PUBLISH_PLATFORMS)" --update-readme=false

docker-upload-readme:
	$(SHIPKIT) docker-hub-readme -repo "$(DOCKER_IMAGE)" -readme README.md

docker-release: docker-publish docker-upload-readme

# Shipkit CI hooks
ci-build: build
ci-test: test
ci-release:
	@test -n "$(TAG)" || (echo "Usage: make ci-release TAG=v0.0.1" && exit 1)
	$(MAKE) docker-release TAG=$(TAG)
