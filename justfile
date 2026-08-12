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
