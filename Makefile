.PHONY: all
all:
	mkdir -p bin
	go build -o bin/auditor cmd/main/main.go

.PHONY: clean
clean:
	go clean -modcache
	rm -f bin/auditor

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: fmt
fmt:
	gofmt -w ./$*

.PHONY: vet
vet:
	go vet ./...

.PHONY: help
help:
	@echo "Makefile targets"
	@echo ""
