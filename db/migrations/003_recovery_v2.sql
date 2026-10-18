-- Organization recovery format 2 (docs/CRYPTO.md). One-way: format-1 shares
-- and recovery envelopes are deleted, and custodians enroll again. Roll back
-- by restoring the pg_dump taken before deploy.

DROP TABLE recovery_custodians;
DELETE FROM vault_recovery_envelopes;
ALTER TABLE organizations DROP COLUMN recovery_ready;

-- One row per recovery key. pending -> confirmed (both custodians) -> active
-- (first recovery envelope) -> degraded (custodian or creator left) or spent
-- (used for a recovery) -> retired (replaced by a newer epoch).
CREATE TABLE recovery_epochs (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    epoch integer NOT NULL,
    public_key bytea NOT NULL,
    fingerprint text NOT NULL,
    created_by uuid NOT NULL REFERENCES users (id),
    creator_public_key bytea NOT NULL,
    creator_fingerprint text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, epoch),
    CONSTRAINT epoch_positive CHECK (epoch > 0),
    CONSTRAINT recovery_public_key_len CHECK (length(public_key) = 32),
    CONSTRAINT creator_public_key_len CHECK (length(creator_public_key) = 32),
    CONSTRAINT epoch_status CHECK (status IN ('pending', 'confirmed', 'active', 'degraded', 'spent', 'retired'))
);

-- At most one epoch in use and one being set up.
CREATE UNIQUE INDEX recovery_epochs_one_current ON recovery_epochs (organization_id)
    WHERE status IN ('active', 'degraded', 'spent');
CREATE UNIQUE INDEX recovery_epochs_one_next ON recovery_epochs (organization_id)
    WHERE status IN ('pending', 'confirmed');

CREATE TABLE recovery_custodians (
    organization_id uuid NOT NULL,
    epoch integer NOT NULL,
    share_index smallint NOT NULL,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    share_nonce bytea NOT NULL,
    share_ciphertext bytea NOT NULL,
    confirmed_at timestamptz,
    PRIMARY KEY (organization_id, epoch, share_index),
    FOREIGN KEY (organization_id, epoch) REFERENCES recovery_epochs (organization_id, epoch) ON DELETE CASCADE,
    CONSTRAINT custodian_share_index CHECK (share_index IN (1, 2)),
    CONSTRAINT custodian_share_nonce_len CHECK (length(share_nonce) = 24),
    CONSTRAINT custodian_distinct_user UNIQUE (organization_id, epoch, user_id),
    CONSTRAINT custodian_distinct_key UNIQUE (organization_id, epoch, fingerprint)
);

-- Recovery envelopes are sealed boxes now; the secretbox nonce goes away.
ALTER TABLE vault_recovery_envelopes DROP COLUMN nonce;
ALTER TABLE vault_recovery_envelopes ADD COLUMN epoch integer NOT NULL;

CREATE TABLE recovery_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    vault_id uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    epoch integer NOT NULL,
    custodian_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    digest bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recovery_challenges_rate ON recovery_challenges (custodian_id, created_at);

CREATE TABLE recovery_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    vault_id uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    epoch integer NOT NULL,
    custodian_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recovery_grants_lookup ON recovery_grants (custodian_id, vault_id);
