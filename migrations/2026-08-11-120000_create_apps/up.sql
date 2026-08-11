-- An `app` is one registered OAuth integration with a specific third-party
-- provider (e.g. "google-workspace", "exact-online"). It holds everything
-- wowauth needs to speak that provider's dialect of OAuth 2.0, plus the
-- caller's public key, used to encrypt tokens wowauth hands back for it.
--
-- Every other table hangs off `apps.id` via a foreign key, which is what
-- keeps separate OAuth instances from ever being mixed up with each other.
CREATE TABLE apps (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,

    -- Client registration at the third-party provider.
    client_id TEXT NOT NULL,
    client_secret BLOB NOT NULL,

    -- Generalizability: every provider has its own endpoints and scopes.
    auth_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    redirect_url TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',

    -- Some providers expect client credentials as an HTTP Basic auth header,
    -- others expect them in the POST body.
    token_auth_method TEXT NOT NULL DEFAULT 'basic'
        CHECK (token_auth_method IN ('basic', 'post')),

    -- Generalizability: extra query params on the authorize request and
    -- extra headers on the token request, both as JSON objects, for
    -- providers that need something beyond the standard OAuth 2.0 shape.
    extra_auth_params TEXT NOT NULL DEFAULT '{}',
    extra_headers TEXT NOT NULL DEFAULT '{}',

    -- Caller-supplied public key. Tokens wowauth returns for this app are
    -- encrypted to this key, so only whoever holds the matching private key
    -- can read them back out. Public by design, so it's stored as plain
    -- text rather than encrypted like the columns above.
    public_key TEXT NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
