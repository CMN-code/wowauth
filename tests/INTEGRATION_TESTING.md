# Writing a wowauth integration test

Context for an LLM agent asked to extend this suite. Read `tests/lifecycle.test.ts` first --
it's the canonical style reference, walking the same lifecycle as
`docs/examples/DEFAULT.md` but driven over HTTP instead of curl -- then read this for the
gotchas that aren't obvious from the code alone.

## What this repo is

A standalone Rust OAuth "receiver" (`poem-openapi`). Read `docs/DESCRIPTION.md` and
`docs/SCHEMA.md` first if you haven't -- they explain the two-sided API (the public
`/{app_id}/oauth/*` facade vs. the `CONFIG_SECRET`-gated `/apps/*` management API) and the
security model (at-rest encryption, HPKE-to-caller token sealing, PKCE) that these tests
exist to verify.

## Before writing any test code

1. **Read the handler you're testing** (`src/oauth_handlers.rs` for `/oauth/*`,
   `src/handlers.rs` for `/apps/*`) for the exact validation order and error shape. Where a
   handler's extractors matter for a test (see the AdminAuth-before-body-parse note below),
   the ordering is in the function signature, not the OpenAPI schema.
2. **The upstream provider is always the mock one** (`src/mock-provider.ts`), never a real
   third party. If your test needs the upstream to behave a particular way (short-lived
   tokens, a rejected refresh, a denied authorize request), that's `provider.behavior`, not
   a new fixture account somewhere.

## Gotchas

- **Two separate PKCE pairs exist in one flow.** wowauth is a PKCE *client* against the
  mock provider (`oauth_client.rs::build_authorization_request` sets its own
  challenge/verifier, stored encrypted in `oauth_flows.pkce_verifier`) **and** a PKCE
  *server* against whatever calls `/oauth/auth` (`caller_code_challenge`, verified in
  `pkce::verify_s256` at `/oauth/token`). `src/oauth-flow.ts`'s `verifier` is the
  *downstream* one -- the one a real script/caller would generate and hold, matching
  `docs/examples/DEFAULT.md` step 4. You never see or need the upstream one; the mock
  provider doesn't enforce it.
- **AdminAuth runs before body parsing.** In every `/apps/*` handler, `_auth: AdminAuth` is
  declared before the `Json<...>` body parameter, and poem-openapi extracts params in
  declaration order -- so a 401 test can send a garbage/empty body and still get a clean
  401 rather than a 400 from failed body validation. `admin-api.test.ts` relies on this
  (see its top comment). If a handler's signature ever reorders these, that test needs to
  follow.
- **`expires_in` can't go negative to fake an already-expired token.** The mock provider's
  JSON response for `expires_in` round-trips through `oauth2`'s `StandardTokenResponse`,
  which expects a non-negative integer; a negative value fails to deserialize entirely
  (surfaces as a `server_error` redirect from `/oauth/callback`, not a usable expired
  token). `refresh.test.ts` instead sets `provider.behavior.expiresIn = 1` and does a real
  ~1.2s wall-clock wait. Keep waits short but comfortably past 1s -- CI jitter is real.
- **`is_active`/user status is optimistic about refresh tokens.** `handlers.rs`'s
  `is_active()` treats "expired but holds *a* refresh_token" as active, regardless of
  whether that refresh token still actually works upstream. Only `GET .../token` finds out
  authoritatively by trying. Don't assert `/status` reflects a refresh failure -- assert
  the `/token` endpoint's response code instead (see `refresh.test.ts`'s last two tests).
- **HPKE wire format**: `token_seal.rs` returns `base64(encapsulated_key(32 bytes) ||
  ciphertext)`. `src/keys.ts::decryptToken` slices the first 32 bytes off before handing
  the rest to `hpke-js`. If wowauth ever switches KEMs, that constant (and the `info`
  string, `"wowauth token v1"`) both need to change in lockstep on the TS side.
- **openapi-fetch's empty-body handling.** Unlike the version of openapi-fetch FUSE's tests
  warned about, the one pinned here (`^0.17`) already falls back to `.text()` when
  `Content-Length` is absent/zero and returns `data: undefined`/`error: undefined` instead
  of throwing -- useful since several wowauth responses (`RevokeResponse::Ok`,
  `UserTokenResponse::NeedsReauth`) have no body. Still, when you only care about the
  status code of a response whose body shape you haven't checked, read
  `res.response.status` rather than asserting on `res.data`/`res.error`.
- **Tests within a describe block are intentionally ordered and stateful**, same spirit as
  FUSE's single big ordered `it` per adapter, just split into smaller `it`s for
  readability here (e.g. `refresh.test.ts`'s rotation tests build on the DB state left by
  the previous one). Don't reach for `it.concurrent` or assume independence across `it`s in
  the same file without checking.
- **Port collision with a dev server.** `src/main.rs` reads `LISTEN_PORT` (defaulting to
  3000) specifically so this suite can run on its own port (3099 by default,
  `src/test-env.ts`) without fighting a `just dev`/`just run` instance on 3000.

## Running it

From the repo root: `just integration-test` (`cd tests && bun run ci`: install -> generate
`schema/api.d.ts` from the live OpenAPI spec -> `vitest run`, all test files). No env vars
or real credentials required -- everything the suite needs it generates or spawns itself.
`just integration-test-fast [test_name]` skips reinstall/regenerate for quicker iteration
once `schema/api.d.ts` already exists.

In a sandboxed shell, `bun`/`cargo`/`just` are only reliably on `PATH` inside a flox
environment: prefix commands with `flox activate -- ...` if they're not found directly.
