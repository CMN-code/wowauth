# wowauth integration tests

Real HTTP requests against a real, running wowauth instance -- no mocks of wowauth itself.
The one thing that *is* mocked is "the upstream OAuth provider" (Airtable, Nmbrs, ... in
real usage): `src/mock-provider.ts` stands in for whichever third party a given app is
registered against, since there's no generic real sandbox provider to test against for
free the way FUSE's tests use real sandboxed Airtable/BigQuery accounts.

The suite is fully self-contained: `src/test-env.ts` provides fixed, non-secret
`CONFIG_SECRET`/`WOWAUTH_MASTER_KEY` values and `src/server-lifecycle.ts` spawns wowauth
against a fresh temp-dir SQLite file per run. No `.env` or real credentials are required.

## Running

```sh
just integration-test
```

or, from inside `tests/` directly:

```sh
bun install
bun run ci        # generate -> vitest run
bunx vitest run    # once schema/api.d.ts already exists, to iterate faster
```

See `INTEGRATION_TESTING.md` for the gotchas worth knowing before adding to this suite.
