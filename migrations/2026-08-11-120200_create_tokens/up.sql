-- The actual credential vault: one row per end-user account that has
-- completed an authorization for a given app. A single `app` (one
-- client_id/client_secret pair at a provider) can and usually will have
-- many independently-authorized accounts under it, so tokens are keyed by
-- (app_id, external_account) rather than by app alone.
--
-- access_token/refresh_token are encrypted at rest, so a stolen database
-- file alone isn't enough to impersonate any of these accounts.
CREATE TABLE tokens (
    id TEXT PRIMARY KEY NOT NULL,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,

    -- Caller-defined identifier for whose grant this is, e.g. the user's
    -- email at the provider, or an internal user id.
    external_account TEXT NOT NULL,

    access_token BLOB NOT NULL,
    refresh_token BLOB,
    -- Scopes actually granted, which may differ from what was requested.
    scopes TEXT NOT NULL,
    expires_at TIMESTAMP,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- One current grant per (app, external account); re-authorizing
    -- updates this row rather than creating an ambiguous duplicate.
    UNIQUE (app_id, external_account)
);

CREATE INDEX idx_tokens_app_id ON tokens(app_id);
