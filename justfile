# List available commands.
default:
    @just --list

# Build the release binary.
build:
    cd cli && cargo build --release --locked

# Run the test suite.
test:
    cd cli && cargo test --locked

# Check formatting and compilation.
check:
    cd cli && cargo fmt --check
    cd cli && cargo check --locked

# Format the Rust sources.
fmt:
    cd cli && cargo fmt
