.PHONY: build test ci install

ZIG_CACHE_ENV = ZIG_GLOBAL_CACHE_DIR=.zig-global-cache ZIG_LOCAL_CACHE_DIR=.zig-cache

build:
	$(ZIG_CACHE_ENV) zig build -Doptimize=ReleaseFast

test:
	$(ZIG_CACHE_ENV) zig build test --summary all

ci:
	$(ZIG_CACHE_ENV) zig build test --summary all
	$(ZIG_CACHE_ENV) zig build -Doptimize=ReleaseFast

install: build
	install -Dm644 "./zig-out/lib/libself.a" "$(HOME)/.local/lib/libself.a"

# Release
# ==================================================================================================
TYPE ?= patch
HAS_REL := $(shell command -v git-rel 2>/dev/null)

release:
	@if [ -z "$(HAS_REL)" ]; then \
		echo "git-rel is not installed. Please install it first."; \
		exit 1; \
	fi
	@if [ -z "$(TYPE)" ]; then \
		echo "Release type not specified. Use 'make release TYPE=[patch|minor|major|m.m.p]'"; \
		exit 1; \
	fi
	@git rel $(TYPE)
