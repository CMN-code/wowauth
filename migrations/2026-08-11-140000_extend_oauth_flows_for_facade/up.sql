-- Supports the /oauth/* facade: wowauth is the client on the upstream leg
-- (talking to the real provider) and the "server" on the downstream leg
-- (talking to whatever called /oauth/auth). `state`/`pkce_verifier` are
-- already the upstream-leg values wowauth generated itself; these columns
-- are the matching downstream-leg values, needed to complete that side of
-- the handshake once the upstream callback comes back.
ALTER TABLE oauth_flows ADD COLUMN caller_state TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_flows ADD COLUMN caller_code_challenge TEXT NOT NULL DEFAULT '';

-- Set once the upstream exchange succeeds: a single-use code handed to the
-- caller, and the resulting user record it's redeemable for. The row is
-- kept alive (rather than deleted) until /oauth/token redeems this code or
-- it expires, at which point it's deleted either way.
ALTER TABLE oauth_flows ADD COLUMN issued_code TEXT;
ALTER TABLE oauth_flows ADD COLUMN token_id TEXT REFERENCES tokens(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX idx_oauth_flows_issued_code ON oauth_flows(issued_code);
