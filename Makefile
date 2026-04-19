.PHONY: all build test test-integration lint check check-integration install install-local clean fmt vet bench eval-prompt

BIN      := claude-guard
BIN_DIR  := $(HOME)/.claude/bin
OUT_DIR  := bin
PKG      := github.com/RobinUS2/claude-guard
MAIN_PKG := $(PKG)/cmd/claude-guard
VERSION  := $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X $(PKG)/internal/version.Version=$(VERSION)

all: check build

build:
	@mkdir -p $(OUT_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(OUT_DIR)/$(BIN) $(MAIN_PKG)

install: build
	@mkdir -p $(BIN_DIR)
	install -m 755 $(OUT_DIR)/$(BIN) $(BIN_DIR)/$(BIN)
	@echo "installed: $(BIN_DIR)/$(BIN)"

install-local: build
	@mkdir -p $(BIN_DIR)
	install -m 755 $(OUT_DIR)/$(BIN) $(BIN_DIR)/$(BIN)

test:
	go test -race ./...

test-short:
	go test -short ./...

# Integration tests shell out (e.g. `go run`) and are gated by build tag.
# Not run by default `make test` / `make check` because they're slower.
test-integration:
	go test -tags=integration ./...

bench:
	go test -bench=. -benchmem -run=^$$ ./...

lint:
	go vet ./...
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "(golangci-lint not installed; skipping)"

fmt:
	gofmt -w .

vet:
	go vet ./...

check: fmt vet test

check-integration: check test-integration

eval-prompt:
	@echo "(eval-prompt target: runs classifier against configs/eval-corpus — implemented in Phase 2)"

clean:
	rm -rf $(OUT_DIR) coverage.out coverage.html
