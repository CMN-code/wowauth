set dotenv-load

_default:
    @just --list


# The commit hash is used as docker image tags and deployment versions!
commit_hash := `[ -f .commithash ] && cat .commithash || git rev-parse --short HEAD`
# Extract version from Cargo.toml
version := `sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1`
# Used for displaying build info inside the app
build_name := version + "-" + commit_hash + " " + `date '+%d-%m-%Y %H:%M'`

image := "ghcr.io/cmn-code/fuse/wowauth"

#
# Building and packaging
#

# Target used by CI for buildling static release binary
build:
    cargo zigbuild --release --target=x86_64-unknown-linux-musl

flox-build:
    BUILD_INFO="{{ build_name }}" flox build
    mkdir -p ./build/artifacts
    cp ./result-wowauth/bin/.wowauth-wrapped ./build/artifacts/wowauth
    chmod +w ./build/artifacts/wowauth

package: flox-build
    BUILD_HASH={{ commit_hash }} docker compose -f build/docker-compose.yml build
    @echo "Tagging image with: '{{ image }}:{{ commit_hash }} {{ image }}:latest'"
    docker tag {{ image }}:{{ commit_hash }} {{ image }}:latest

# Build, package and push to GHCR
release: package
    docker push {{ image }}:{{ commit_hash }}
    docker push {{ image }}:latest

package-run tag="latest":
    docker run --rm -it -p 3000:3000 ghcr.io/cmn-code/fuse/wowauth:{{tag}}

#
# Formatting, linting and testing
#

format:
    @cargo fmt

lint: format
    @cargo clippy --all-targets --all-features -- -D warnings

fix:
    @cargo clippy --all-targets --all-features --fix -- -D warnings


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
    rm result-wowauth*
