-- The authorization_code grant is a two-step dance split across a browser
-- redirect: wowauth starts a flow, the user's browser goes off to the
-- provider, and later comes back with a `code` and `state`. This table is
-- the memory that bridges those two requests. Each row is single-use and
-- short-lived (see `expires_at`); the callback handler should delete it as
-- soon as it's consumed, so a `code`/`state` pair can never be replayed.
--
-- Keeping this separate from `tokens` matters: a row here is a live,
-- CSRF-sensitive secret mid-flight, not yet a granted credential, and it
-- should never be mistaken for one.
CREATE TABLE oauth_flows (
    id TEXT PRIMARY KEY NOT NULL,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,

    -- CSRF token, sent as the OAuth `state` param and checked on callback.
    state TEXT NOT NULL UNIQUE,
    -- PKCE code_verifier, needed to complete the token exchange.
    pkce_verifier BLOB NOT NULL,

    -- Where wowauth reports the result back to once the flow completes,
    -- since wowauth is a broker for many callers per app.
    redirect_after TEXT NOT NULL,
    -- Caller-supplied label for which end-user/account this is for.
    external_account_hint TEXT,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_oauth_flows_app_id ON oauth_flows(app_id);
CREATE INDEX idx_oauth_flows_expires_at ON oauth_flows(expires_at);
