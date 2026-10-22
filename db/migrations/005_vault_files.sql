-- Documents attached to accounts (docs/CRYPTO.md "Account documents"). Each
-- file is encrypted in the browser with its own random key; that key lives in
-- the account's vault item, so the server holds only ciphertext it cannot
-- open. Deleting the account deletes its files.
CREATE TABLE vault_files (
    id uuid PRIMARY KEY,
    vault_id uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES service_accounts (id) ON DELETE CASCADE,
    size bigint NOT NULL,
    content bytea NOT NULL,
    created_by uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT vault_files_size CHECK (size = octet_length(content))
);

CREATE INDEX vault_files_account ON vault_files (account_id);
CREATE INDEX vault_files_vault ON vault_files (vault_id);
