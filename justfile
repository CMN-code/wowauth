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

# End-to-end integration tests: spawns a real wowauth instance against a throwaway
# SQLite file plus a mock upstream OAuth provider, then drives real HTTP requests
# against it. See tests/INTEGRATION_TESTING.md. Needs bun (`flox activate` provides it).
integration-test:
    cd tests && bun run ci

# Same, without reinstalling deps or regenerating the OpenAPI client -- for iterating.
integration-test-fast test_name="":
    cd tests && bunx vitest run {{ test_name }}

# Interactive, narrated setup wizard for connecting a Nmbrs account to a running
# wowauth instance -- see docs/examples/nmbrs-setup.ts and docs/examples/NMBRS.md.
nmbrs-setup:
    @bun run docs/examples/nmbrs-setup.ts

#
# Development
#

# Runs the server, restarting on source changes
dev:
    @watchexec -r -e rs -- cargo run

run:
    @cargo run

#
# Database
#
# Pending migrations are applied at startup always, so these are
# only needed for local schema work: scaffolding a migration and keeping
# src/schema.rs in sync

# Scaffolds a new migration; fill in the generated up.sql/down.sql, then run `just db-migrate`.
db-new name:
    @diesel migration generate {{ name }}

# Applies pending migrations and regenerates src/schema.rs to match.
db-migrate:
    @diesel migration run

# Reverts and re-runs the latest migration, to check that down.sql actually works.
db-redo:
    @diesel migration redo

# Drops and recreates the local database from scratch.
db-reset:
    @diesel database reset

#
# Housekeeping
#

clean:
    cargo clean
    rm -rf .flox/cache

build:
    cargo build --release
