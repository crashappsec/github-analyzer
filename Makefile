.PHONY: all
all: ## compile auditor
	mkdir -p bin
	go build -o bin/github-analyzer cmd/github-analyzer/main.go

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
vet: ## go vet
	go vet ./...

.PHONY: help
help: ## show help
	@grep -E '^[a-zA-Z_\-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		cut -d':' -f1- | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'
