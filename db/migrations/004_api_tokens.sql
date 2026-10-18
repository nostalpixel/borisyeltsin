-- Personal access tokens for the MCP endpoint (docs/MCP.md). A token acts as
-- its owner with the owner's role and grants; the server stores only its
-- SHA-256. Tokens never reach the vault.
CREATE TABLE api_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    can_write boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT api_token_hash_len CHECK (length(token_hash) = 32),
    CONSTRAINT api_token_name_len CHECK (length(name) BETWEEN 1 AND 80)
);
CREATE INDEX api_tokens_user ON api_tokens (user_id);
