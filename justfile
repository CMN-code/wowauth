set dotenv-load

_default:
    @just --list

#
# Formatting, linting and testing
#

format:
    @cargo fmt

lint: format
    @cargo clippy --all-targets --all-features -- -D warnings

fix:
    @cargo clippy --all-targets --all-features --fix -- -D warnings

test:
    @cargo nextest run

#
# Development
#

# Runs the server, restarting on source changes
dev:
    @watchexec -r -e rs -- cargo run

run:
    @cargo run

#
# Housekeeping
#

clean:
    cargo clean
    rm -rf .flox/cache

build:
    cargo build --release
