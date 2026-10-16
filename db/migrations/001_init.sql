CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    recovery_ready boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id),
    issuer text NOT NULL,
    subject text NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    role text NOT NULL DEFAULT 'member',
    status text NOT NULL DEFAULT 'pending_enrollment',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_role CHECK (role IN ('admin', 'manager', 'member', 'readonly')),
    CONSTRAINT users_status CHECK (status IN ('pending_enrollment', 'pending_approval', 'active', 'revoked')),
    CONSTRAINT users_identity UNIQUE (issuer, subject)
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_secret text NOT NULL,
    amr text[] NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oidc_transactions (
    state_hash bytea PRIMARY KEY,
    nonce text NOT NULL,
    code_verifier text NOT NULL,
    invite_token_hash bytea,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE invitations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id),
    token_hash bytea NOT NULL UNIQUE,
    intended_issuer text NOT NULL,
    intended_subject text NOT NULL,
    intended_email text NOT NULL,
    role text NOT NULL DEFAULT 'member',
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz,
    created_by uuid REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT invitations_role CHECK (role IN ('admin', 'manager', 'member', 'readonly'))
);

CREATE TABLE crypto_identities (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    public_key bytea NOT NULL,
    fingerprint text NOT NULL,
    kdf_algorithm text NOT NULL,
    kdf_opslimit integer NOT NULL,
    kdf_memlimit integer NOT NULL,
    kdf_salt bytea NOT NULL,
    private_key_nonce bytea NOT NULL,
    private_key_ciphertext bytea NOT NULL,
    recovery_nonce bytea NOT NULL,
    recovery_ciphertext bytea NOT NULL,
    key_version integer NOT NULL DEFAULT 1,
    status text NOT NULL DEFAULT 'pending',
    approved_by uuid REFERENCES users (id),
    approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT crypto_status CHECK (status IN ('pending', 'approved', 'rejected')),
    CONSTRAINT crypto_kdf CHECK (kdf_algorithm = 'argon2id' AND kdf_opslimit >= 3 AND kdf_memlimit >= 67108864)
);

CREATE TABLE crypto_proposals (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    public_key bytea NOT NULL,
    fingerprint text NOT NULL,
    kdf_algorithm text NOT NULL,
    kdf_opslimit integer NOT NULL,
    kdf_memlimit integer NOT NULL,
    kdf_salt bytea NOT NULL,
    private_key_nonce bytea NOT NULL,
    private_key_ciphertext bytea NOT NULL,
    recovery_nonce bytea NOT NULL,
    recovery_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT proposal_kdf CHECK (kdf_algorithm = 'argon2id' AND kdf_opslimit >= 3 AND kdf_memlimit >= 67108864)
);

CREATE TABLE vaults (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id),
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    key_version integer NOT NULL DEFAULT 1,
    rotation_required boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz
);

CREATE TABLE vault_members (
    vault_id uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role text NOT NULL,
    PRIMARY KEY (vault_id, user_id),
    CONSTRAINT vault_role CHECK (role IN ('owner', 'manager', 'member'))
);

CREATE TABLE vault_key_envelopes (
    vault_id uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key_version integer NOT NULL,
    recipient_fingerprint text NOT NULL,
    ciphertext bytea NOT NULL,
    created_by uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, user_id, key_version)
);

CREATE TABLE vault_recovery_envelopes (
    vault_id uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    key_version integer NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    PRIMARY KEY (vault_id, key_version)
);

CREATE TABLE recovery_custodians (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    share_index smallint NOT NULL,
    share_ciphertext bytea NOT NULL,
    fingerprint text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id),
    CONSTRAINT share_index_chk CHECK (share_index IN (1, 2)),
    CONSTRAINT one_share_index UNIQUE (organization_id, share_index)
);

CREATE TABLE vault_items (
    id uuid PRIMARY KEY,
    vault_id uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    key_version integer NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    created_by uuid NOT NULL REFERENCES users (id),
    updated_by uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);

CREATE TABLE services (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id),
    name text NOT NULL,
    category text NOT NULL DEFAULT 'other',
    url text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    unclear boolean NOT NULL DEFAULT false,
    logo text NOT NULL DEFAULT '',
    logo_bg text NOT NULL DEFAULT '#eeeafc',
    logo_fg text NOT NULL DEFAULT '#7663c6',
    owner_id uuid REFERENCES users (id),
    notes text NOT NULL DEFAULT '',
    tags text[] NOT NULL DEFAULT '{}',
    archived_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT services_category CHECK (category IN ('infra', 'domains', 'tools', 'comms', 'partners', 'payments', 'other')),
    CONSTRAINT services_logo_bg CHECK (logo_bg ~ '^#[0-9a-fA-F]{6}$'),
    CONSTRAINT services_logo_fg CHECK (logo_fg ~ '^#[0-9a-fA-F]{6}$')
);

CREATE TABLE service_grants (
    service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (service_id, user_id)
);

CREATE TABLE service_accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    label text NOT NULL,
    login_hint text NOT NULL DEFAULT '',
    card_label text NOT NULL DEFAULT '',
    notes text NOT NULL DEFAULT '',
    vault_id uuid REFERENCES vaults (id),
    vault_item_id uuid REFERENCES vault_items (id) ON DELETE SET NULL,
    position integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE payment_methods (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id),
    nickname text NOT NULL,
    issuer text NOT NULL DEFAULT '',
    last4 text NOT NULL,
    exp_month integer NOT NULL,
    exp_year integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT last4_chk CHECK (last4 ~ '^[0-9]{4}$'),
    CONSTRAINT exp_month_chk CHECK (exp_month BETWEEN 1 AND 12),
    CONSTRAINT exp_year_chk CHECK (exp_year BETWEEN 2000 AND 2100)
);

CREATE TABLE subscriptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    account_id uuid REFERENCES service_accounts (id) ON DELETE CASCADE,
    payment_method_id uuid REFERENCES payment_methods (id),
    name text NOT NULL DEFAULT '',
    billing_cycle text NOT NULL,
    custom_interval_days integer,
    renewal_date date NOT NULL,
    cost_minor bigint NOT NULL,
    currency text NOT NULL,
    auto_renew boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT billing_cycle_chk CHECK (billing_cycle IN ('monthly', 'quarterly', 'annual', 'custom')),
    CONSTRAINT currency_chk CHECK (currency ~ '^[A-Z]{3,5}$'),
    CONSTRAINT cost_chk CHECK (cost_minor >= 0),
    CONSTRAINT custom_days_chk CHECK (
        (billing_cycle = 'custom' AND custom_interval_days IS NOT NULL AND custom_interval_days > 0)
        OR (billing_cycle <> 'custom' AND custom_interval_days IS NULL)
    )
);

CREATE TABLE payments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id uuid NOT NULL REFERENCES subscriptions (id) ON DELETE CASCADE,
    paid_on date NOT NULL,
    amount_minor bigint NOT NULL,
    currency text NOT NULL,
    note text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT payment_amount_chk CHECK (amount_minor >= 0),
    CONSTRAINT payment_currency_chk CHECK (currency ~ '^[A-Z]{3,5}$')
);

CREATE TABLE renewal_alerts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id),
    subscription_id uuid NOT NULL REFERENCES subscriptions (id) ON DELETE CASCADE,
    days_before integer NOT NULL,
    due_on date NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alert_days CHECK (days_before IN (7, 3, 1)),
    UNIQUE (subscription_id, days_before, due_on)
);

CREATE TABLE credential_flags (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id),
    vault_item_id uuid,
    service_account_id uuid,
    reason text NOT NULL,
    flagged_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE TABLE audit_events (
    id bigserial PRIMARY KEY,
    organization_id uuid NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX users_org_idx ON users (organization_id);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX invitations_org_idx ON invitations (organization_id);
CREATE INDEX services_org_idx ON services (organization_id);
CREATE INDEX subscriptions_renewal_idx ON subscriptions (renewal_date);
CREATE INDEX audit_org_idx ON audit_events (organization_id, created_at DESC);
CREATE INDEX vault_items_vault_idx ON vault_items (vault_id);
