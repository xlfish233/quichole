.PHONY: help build build-release test fmt fmt-check clippy run-svr run-cli clean
.DEFAULT_GOAL := help

CARGO ?= cargo
RUST_LOG ?= info
SVR_CFG ?= server.toml
CLI_CFG ?= client.toml

help:
	@echo "make build          # cargo build"
	@echo "make build-release  # cargo build --release"
	@echo "make test           # cargo test --all"
	@echo "make fmt            # cargo fmt"
	@echo "make fmt-check      # cargo fmt -- --check"
	@echo "make clippy         # cargo clippy -- -D warnings"
	@echo "make run-svr        # run server with server.toml"
	@echo "make run-cli        # run client with client.toml"
	@echo "make clean          # cargo clean"

build:
	$(CARGO) build

build-release:
	$(CARGO) build --release

test:
	$(CARGO) test --all

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt -- --check

clippy:
	$(CARGO) clippy -- -D warnings

run-svr:
	RUST_LOG=$(RUST_LOG) $(CARGO) run -p quichole-svr -- -c $(SVR_CFG)

run-cli:
	RUST_LOG=$(RUST_LOG) $(CARGO) run -p quichole-cli -- -c $(CLI_CFG)

clean:
	$(CARGO) clean
