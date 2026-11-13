# List available commands.
default:
    @just --list

# Build the release binary.
build:
    cargo build --release --locked

# Run the test suite.
test:
    cargo test --locked

# Check formatting and compilation.
check:
    cargo fmt --check
    cargo check --locked

# Format the Rust sources.
fmt:
    cargo fmt
