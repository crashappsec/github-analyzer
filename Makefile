BIN=$(notdir $(wildcard cmd/*))
VERSION=$(shell git describe --tags --long)

.PHONY: all
all: $(addprefix bin/,$(BIN)) ## compile auditor

bin/%: bin generate
	go build \
		-v \
		-ldflags "-X main.version=$(VERSION)" \
		-o $@ \
		cmd/$*/main.go

bin:
	mkdir -p bin

.PHONY: generate
generate: ## process go:generate files
	go generate ./...

.PHONY: lint
lint: ## lint everything with pre-commit
	pre-commit run --all-files --show-diff-on-failure

.PHONY: clean
clean: ## clean go cache and compile artifacts
	go clean -modcache
	rm -f bin/github-analyzer

.PHONY: tidy
tidy: ## tidy go deps
	go mod tidy

.PHONY: fmt
fmt: ## go format
	gofmt -w ./$*

.PHONY: vet
vet: generate ## go vet
	go vet ./...

.PHONY: test
test: generate ## run go tests (requires GitHub to be reachable via the network)
	go test -v -race -coverprofile coverage.txt ./...

.PHONY: help
help: ## show help
	@grep -E '^[a-zA-Z_\-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		cut -d':' -f1- | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'
