-- Allow-list of redirect URIs the /oauth/* facade accepts back from calling
-- clients, as opposed to `redirect_url` (singular), which is the callback
-- wowauth itself registers with the upstream provider. JSON array of
-- strings, same convention as extra_auth_params/extra_headers.
ALTER TABLE apps ADD COLUMN allowed_redirect_uris TEXT NOT NULL DEFAULT '[]';
