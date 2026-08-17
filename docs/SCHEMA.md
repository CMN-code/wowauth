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
"Secrets" below). `public_key` is the caller-supplied X25519 public key that
tokens returned for this app get HPKE-encrypted to (`src/token_seal.rs`) —
it's stored as plain text, since it's public by design. `redirect_url` is
wowauth's own callback registered with the upstream provider;
`allowed_redirect_uris` (JSON array) is the separate allow-list of redirect
URIs the `/oauth/*` facade will accept back from calling clients.

### `oauth_flows`

The authorization code flow is split across a browser redirect, and wowauth
sits in the middle of *two* such flows at once: it's the client on the
upstream leg (talking to the real provider) and the "server" on the
downstream leg (talking to whatever called `/oauth/auth`). This table is
the memory that bridges all of that — `state`/`pkce_verifier` are the
upstream-leg values wowauth generated itself; `caller_state`/
`caller_code_challenge` are the matching downstream-leg values.

A row lives through two phases. First, pending: between `/oauth/auth`
redirecting out and `/oauth/callback` receiving the provider's redirect
back. Each row is single-use and short-lived (`expires_at`), so a `state`
can never be replayed. Second, once the upstream exchange succeeds, the
*same* row is updated in place (`issued_code`/`token_id` get set, and
`expires_at` shortens to ~60s) rather than deleted — it now represents a
single-use code redeemable at `/oauth/token` for the resulting `tokens`
row, instead of a pending authorization attempt. Reusing the row this way
keeps a single expiry/single-use model for both phases rather than needing
two.

Keeping this separate from `tokens` matters throughout: a row here is
either a live, CSRF-sensitive secret mid-flight or a short-lived claim
check, never a long-lived granted credential, and it should never be
mistaken for one.

### `tokens`

The actual credential vault — one row per end-user account that has
completed authorization under a given app; this is also the "user" the
management API's `/apps/{app_id}/users/...` endpoints operate on, keyed by
`tokens.id`. A single app (one client_id/secret pair at a provider) can have
many independently-authorized accounts, so tokens are keyed by
`(app_id, external_account)` rather than by app alone; re-authorizing the
same account updates its row instead of creating an ambiguous duplicate.
`label` is an optional human-readable name/email for the account, captured
from the provider during authorization when available.

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

## The `/oauth/*` facade

`src/oauth_handlers.rs` implements the standards-shaped surface from
`docs/DESCRIPTION.md`: `/{app_id}/.well-known/openid-configuration`,
`/{app_id}/oauth/auth`, `/{app_id}/oauth/callback` (not in the original
list, but necessary — it's the fixed URI wowauth itself registers with the
upstream provider as `apps.redirect_url`), `/{app_id}/oauth/token`, and
`/{app_id}/oauth/revoke`. Unauthenticated by design, same as any real
provider's equivalents — the request is documented in
`docs/DESCRIPTION.md`.

Callers of this facade are treated as public clients: no client secret, PKCE
(S256 only) required at `/oauth/auth` and verified at `/oauth/token`
(`src/pkce.rs`), and `redirect_uri` checked against `apps.allowed_redirect_uris`
before wowauth ever redirects anywhere. `/oauth/token` deliberately never
returns a `refresh_token` — wowauth keeps that to itself and handles
renewal server-side (the same auto-refresh the proprietary
`/apps/.../token` endpoint uses, via `src/oauth_client.rs`), rather than
handing a long-lived upstream credential to whichever downstream client
happens to complete a given flow.

## What's built

The schema/migrations, at-rest encryption, connection pooling, the full
management API, and the `/oauth/*` facade above — end to end, verified
against a mock upstream provider: authorize → callback → code exchange →
token, plus replay rejection, redirect_uri allow-list enforcement,
auto-refresh, and revocation.
