.PHONY: build release test clean install fix help

.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build debug binary
	cargo build

release: ## Build optimized release binary
	cargo build --release

test: ## Run tests
	cargo test

fix: ## Auto-fix rustfmt and clippy findings
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged

install: ## Install binary via cargo
	cargo install --path .

clean: ## Remove build artifacts
	cargo clean
