.PHONY: all build test test-integration lint check check-integration install install-local clean fmt vet bench eval-prompt monitor stats

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
	@echo "installed: $(BIN_DIR)/$(BIN) ($(VERSION))"
	@# Verify that the binary Claude Code hooks will invoke is the one
	@# we just built. The vault-gate and other wrappers resolve
	@# `claude-guard` via PATH — a stale copy from `go install` at
	@# ~/go/bin/claude-guard shadows ~/.claude/bin and silently runs
	@# old rules. Warn when the PATH-resolved binary doesn't match.
	@active_bin=$$(command -v $(BIN) 2>/dev/null || true); \
	installed_bin=$(BIN_DIR)/$(BIN); \
	if [ -z "$$active_bin" ]; then \
		echo "warn: $(BIN) not on PATH — add $(BIN_DIR) to PATH or hooks may fail to resolve it"; \
	elif [ "$$active_bin" != "$$installed_bin" ]; then \
		active_ver=$$($$active_bin version 2>/dev/null || echo '?'); \
		installed_ver=$$($$installed_bin version 2>/dev/null || echo '?'); \
		if [ "$$active_ver" != "$$installed_ver" ]; then \
			echo ""; \
			echo "warn: stale $(BIN) shadowing the installed binary on PATH:"; \
			echo "  active (PATH): $$active_bin ($$active_ver)"; \
			echo "  installed:     $$installed_bin ($$installed_ver)"; \
			echo "  fix: cp $$installed_bin $$active_bin  (or remove the stale copy)"; \
		fi; \
	fi
	@# TODO(security plan #18): move this CLAUDE.md splice into the Go binary
	@# (cmd: claude-guard hints --install-claude-md) using os.CreateTemp inside
	@# ~/.claude/ + atomic rename to prevent TOCTOU. For now, mktemp mitigates
	@# the fixed-name /tmp race.
	@#
	@# Regenerate the claude-guard hints section in ~/.claude/CLAUDE.md.
	@# Keeps Claude's auto-approval context fresh after every install.
	@CLAUDE_MD="$(HOME)/.claude/CLAUDE.md"; \
	HINTS_TMP=$$(mktemp /tmp/cg_hints_XXXXXX.md); \
	$(BIN_DIR)/$(BIN) hints --no-history > "$$HINTS_TMP" 2>/dev/null || true; \
	if [ -f "$$CLAUDE_MD" ] && [ -s "$$HINTS_TMP" ]; then \
		START='<!-- claude-guard-hints-start -->'; \
		END='<!-- claude-guard-hints-end -->'; \
		if grep -q 'claude-guard-hints-start' "$$CLAUDE_MD" 2>/dev/null; then \
			CG_MD_TMP=$$(mktemp /tmp/cg_claude_md_XXXXXX); \
			awk -v s="$$START" -v e="$$END" -v f="$$HINTS_TMP" \
				'/<!--.*claude-guard-hints-start.*-->/{print s; while((getline l < f)>0) print l; print e; skip=1; next} \
				 /<!--.*claude-guard-hints-end.*-->/{skip=0; next} \
				 !skip{print}' "$$CLAUDE_MD" > "$$CG_MD_TMP" && \
			mv "$$CG_MD_TMP" "$$CLAUDE_MD" && \
			echo "  updated CLAUDE.md hints section" || rm -f "$$CG_MD_TMP"; \
		else \
			{ printf '\n\n%s\n' "$$START"; cat "$$HINTS_TMP"; printf '%s\n' "$$END"; } >> "$$CLAUDE_MD" && \
			echo "  appended CLAUDE.md hints section"; \
		fi; \
	fi; \
	rm -f "$$HINTS_TMP"

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

# Live-tail decisions.jsonl — use the locally built binary so changes
# you just made are reflected. Accepts extra args via ARGS.
#   make monitor              # tail all decisions
#   make monitor ARGS='--deny' # only denies
monitor: build
	$(OUT_DIR)/$(BIN) monitor $(ARGS)

# Snapshot stats from decisions.jsonl (stop hooks + decide events).
#   make stats                     # default window
#   make stats ARGS='--since 1h'
stats: build
	$(OUT_DIR)/$(BIN) stats $(ARGS)

clean:
	rm -rf $(OUT_DIR) coverage.out coverage.html
