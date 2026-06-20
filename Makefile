.PHONY: build release test clean install

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

clean:
	cargo clean

install:
	cargo install --path .
