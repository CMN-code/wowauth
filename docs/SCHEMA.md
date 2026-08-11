# Database schema

wowauth stores its state in SQLite, accessed through
[Diesel](https://diesel.rs) via a small `r2d2` connection pool
(`src/db.rs`). Diesel was chosen over an async ORM because SQLite has no
concurrent-writer story to be async about in the first place; a synchronous
connection pool is simpler and has fewer moving parts.

Migrations live in `migrations/` and are embedded into the binary
(`diesel_migrations::embed_migrations!`), so `cargo run` always brings the
schema up to date on startup — nobody has to remember to run
`diesel migration run` by hand. `src/schema.rs` is generated from the
migrations by `diesel_cli` (see the `db-*` recipes in the `justfile`); it
shouldn't be hand-edited.

## Why these tables exist

### `apps`

One row per registered third-party OAuth integration (e.g.
"google-workspace", "exact-online"). This is the root entity: it holds the
client_id/secret and endpoints needed to speak OAuth to that specific
provider, and it's what every other table hangs off via a foreign key —
which is what keeps different OAuth "instances" from ever being mixed up
with each other. A bug in a query elsewhere is contained by the schema's
shape, not just by application code remembering to filter correctly.

Two fields exist purely for generalizability, since not every provider
speaks textbook OAuth 2.0:

- `token_auth_method` — some providers want the client_id/secret as an HTTP
  Basic auth header, others want them in the POST body.
- `extra_auth_params` / `extra_headers` — JSON objects for whatever a
  specific provider needs beyond the standard shape (e.g. Google's
  `access_type=offline`, a tenant id for Azure AD, a custom `Accept`
  header).

`client_secret` is stored as an encrypted `BLOB`, not plaintext (see
"Secrets" below). `public_key` is the caller-supplied key that tokens
returned for this app get encrypted to — it's stored as plain text, since
it's public by design.

### `oauth_flows`

The authorization code flow is split across a browser redirect: wowauth
starts a flow, the user's browser goes off to the provider, and later comes
back with a `code` and `state`. This table is the memory that bridges those
two requests — the CSRF `state` token and the PKCE `code_verifier` have to
survive somewhere between "redirect out" and "callback in."

Each row is meant to be single-use and short-lived (`expires_at`); the
callback handler should delete it as soon as it's consumed, so a `code`/
`state` pair can never be replayed. Keeping this separate from `tokens`
matters: a row here is a live, CSRF-sensitive secret mid-flight, not yet a
granted credential, and it should never be mistaken for one.

### `tokens`

The actual credential vault — one row per end-user account that has
completed authorization under a given app. A single app (one client_id/
secret pair at a provider) can have many independently-authorized accounts,
so tokens are keyed by `(app_id, external_account)` rather than by app
alone; re-authorizing the same account updates its row instead of creating
an ambiguous duplicate.

## Secrets

`apps.client_secret`, `oauth_flows.pkce_verifier`, `tokens.access_token`,
and `tokens.refresh_token` are encrypted at rest with ChaCha20-Poly1305
(`src/crypto.rs`), using a master key read from `WOWAUTH_MASTER_KEY`. That
key lives only in the process environment and never touches the database,
so a stolen `.db` file alone is never enough to recover a usable
credential.

`apps.public_key` is deliberately *not* encrypted — it's a public key the
caller registers so wowauth can encrypt tokens to it (only their matching
private key can decrypt them), so there's no confidentiality requirement
for wowauth's own storage of it.

## What's built vs. what's next

Done and tested: the schema/migrations, at-rest encryption, connection
pooling, and app registration (`POST /apps`, `GET /apps/:name`).

`docs/DESCRIPTION.md` describes a considerably larger surface on top of
this — per-app OAuth-facade endpoints (`/oauth/auth`, `/oauth/token`, ...),
a `users` sub-resource per app, bearer-auth-gated management endpoints, and
an OpenAPI schema via `poem-openapi`. None of that is built yet; today's
work is the storage layer it all sits on.
