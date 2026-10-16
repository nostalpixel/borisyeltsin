-- Sessions store the SHA-256 of a 32-byte cookie token. Old rows held the
-- cookie value itself, so every existing session ends here.
DELETE FROM sessions;
ALTER TABLE sessions ADD COLUMN token_hash bytea NOT NULL;
ALTER TABLE sessions ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);
ALTER TABLE sessions ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Each item write bumps version. Writers send the version they read.
ALTER TABLE vault_items ADD COLUMN version integer NOT NULL DEFAULT 1;

-- A vault accepts its first key envelope once. After that a missing envelope
-- means "no access", never "new vault".
ALTER TABLE vaults ADD COLUMN initialized boolean NOT NULL DEFAULT false;
UPDATE vaults v SET initialized = true
WHERE EXISTS (SELECT 1 FROM vault_key_envelopes e WHERE e.vault_id = v.id)
   OR EXISTS (SELECT 1 FROM vault_items i WHERE i.vault_id = v.id);
