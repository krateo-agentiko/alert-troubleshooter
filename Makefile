# Set the shell to bash always
SHELL := /bin/bash

# Every file `make generate` writes.
GENERATED := ':(glob)apis/**/zz_generated.*.go'

IMAGE ?= ghcr.io/krateo-platformops/alert-provider
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: help
help: ## print this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: generate
generate: ## generate the deepcopy methodsets
	cd apis && go generate -tags generate ./...

.PHONY: check-generate
check-generate: generate ## fail if the committed generated files differ from a fresh generate
	@git diff --exit-code -- $(GENERATED) || { echo "generated files are stale: run 'make generate' and commit"; exit 1; }

.PHONY: build
build: ## build all packages
	go build ./...

.PHONY: test
test: ## run unit tests
	go test -race -cover ./...

.PHONY: lint
lint: ## run go vet
	go vet ./...

.PHONY: lint-charts
lint-charts: ## helm lint and render every chart, with CHART_VERSION set to 0.0.0
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	  for c in helm/*/; do \
	    n="$$(basename "$$c")"; cp -R "$$c" "$$tmp/$$n"; \
	    sed -i.bak 's/CHART_VERSION/0.0.0/g' "$$tmp/$$n/Chart.yaml"; \
	    helm lint --strict "$$tmp/$$n" && helm template "$$n" "$$tmp/$$n" >/dev/null || exit 1; \
	  done

.PHONY: image
image: ## build the image
	docker build -t $(IMAGE):$(VERSION) .

.PHONY: check
check: build lint test check-generate lint-charts ## everything CI runs
