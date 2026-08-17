-- Human-readable label (name/email) for a user's grant, captured from the
-- provider during authorization when available. Nullable: not every
-- provider exposes profile info, and nothing populates this until the
-- /oauth/* authorize/callback flow exists.
ALTER TABLE tokens ADD COLUMN label TEXT;
