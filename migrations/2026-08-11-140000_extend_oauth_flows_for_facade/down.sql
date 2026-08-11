DROP INDEX idx_oauth_flows_issued_code;
ALTER TABLE oauth_flows DROP COLUMN token_id;
ALTER TABLE oauth_flows DROP COLUMN issued_code;
ALTER TABLE oauth_flows DROP COLUMN caller_code_challenge;
ALTER TABLE oauth_flows DROP COLUMN caller_state;
