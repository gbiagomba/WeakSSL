PACKAGE := weakssl
BIN := target/release/$(PACKAGE)

.PHONY: all build debug run test fmt clean

all: build

build:
	cargo build --release

debug:
	cargo build

run: build
	$(BIN) $(ARGS)

test:
	cargo test --all

fmt:
	cargo fmt --all || true

clean:
	cargo clean

