-- name: CountOrganizations :one
SELECT count(*)::bigint FROM organizations;

-- name: CountAllUsers :one
SELECT count(*)::bigint FROM users;

-- name: FirstOrganization :one
SELECT * FROM organizations ORDER BY created_at LIMIT 1;

-- name: CreateOrganization :one
INSERT INTO organizations (name) VALUES ($1) RETURNING *;

-- name: GetOrganization :one
SELECT * FROM organizations WHERE id = $1;

-- name: CountUsers :one
SELECT count(*)::bigint FROM users WHERE organization_id = $1;

-- name: CreateUser :one
INSERT INTO users (organization_id, issuer, subject, email, display_name, role, status)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetUserByIdentity :one
SELECT * FROM users WHERE issuer = $1 AND subject = $2;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1 AND organization_id = $2;

-- name: ListUsers :many
SELECT * FROM users WHERE organization_id = $1 ORDER BY created_at;

-- name: UpdateUserRole :one
UPDATE users SET role = $3, updated_at = now()
WHERE id = $1 AND organization_id = $2
RETURNING *;

-- name: UpdateUserStatus :one
UPDATE users SET status = $3, updated_at = now()
WHERE id = $1 AND organization_id = $2
RETURNING *;

-- name: CreateSession :one
INSERT INTO sessions (token_hash, user_id, csrf_secret, amr, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetActiveSession :one
SELECT s.id, s.user_id, s.csrf_secret, s.amr, s.expires_at,
       u.organization_id, u.email, u.display_name, u.role, u.status, u.issuer, u.subject
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.status <> 'revoked';

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeSessionsForUser :exec
UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: InsertOIDCTransaction :exec
INSERT INTO oidc_transactions (state_hash, nonce, code_verifier, invite_token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeOIDCTransaction :one
DELETE FROM oidc_transactions
WHERE state_hash = $1 AND expires_at > now()
RETURNING nonce, code_verifier, invite_token_hash, expires_at;

-- name: DeleteExpiredOIDCTransactions :exec
DELETE FROM oidc_transactions WHERE expires_at <= now();

-- name: CreateInvitation :one
INSERT INTO invitations (
    organization_id, token_hash, intended_issuer, intended_subject, intended_email, role, expires_at, created_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetInvitationByHash :one
SELECT * FROM invitations WHERE token_hash = $1;

-- name: AcceptInvitation :one
UPDATE invitations SET accepted_at = now()
WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
RETURNING *;

-- name: RevokeInvitation :one
UPDATE invitations SET revoked_at = now()
WHERE id = $1 AND organization_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL
RETURNING *;

-- name: RevokeOpenInvitations :exec
UPDATE invitations SET revoked_at = now()
WHERE organization_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL;

-- name: LockBootstrap :exec
SELECT pg_advisory_xact_lock(hashtext('borisyeltsin.bootstrap'));

-- name: ListInvitations :many
SELECT * FROM invitations WHERE organization_id = $1 ORDER BY created_at DESC;

-- name: InsertCryptoIdentity :one
INSERT INTO crypto_identities (
    user_id, public_key, fingerprint, kdf_algorithm, kdf_opslimit, kdf_memlimit, kdf_salt,
    private_key_nonce, private_key_ciphertext, recovery_nonce, recovery_ciphertext, status
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending')
RETURNING *;

-- name: GetCryptoIdentity :one
SELECT * FROM crypto_identities WHERE user_id = $1;

-- name: ApproveCryptoIdentity :one
UPDATE crypto_identities
SET status = 'approved', approved_by = $2, approved_at = now()
WHERE user_id = $1 AND status = 'pending'
RETURNING *;

-- name: RejectCryptoIdentity :one
UPDATE crypto_identities
SET status = 'rejected', approved_by = $2, approved_at = now()
WHERE user_id = $1 AND status = 'pending'
RETURNING *;

-- name: ReplaceCryptoIdentity :one
UPDATE crypto_identities SET
    public_key = $2,
    fingerprint = $3,
    kdf_algorithm = $4,
    kdf_opslimit = $5,
    kdf_memlimit = $6,
    kdf_salt = $7,
    private_key_nonce = $8,
    private_key_ciphertext = $9,
    recovery_nonce = $10,
    recovery_ciphertext = $11,
    key_version = key_version + 1,
    status = 'approved',
    approved_by = $12,
    approved_at = now()
WHERE user_id = $1
RETURNING *;

-- name: UpsertCryptoProposal :one
INSERT INTO crypto_proposals (
    user_id, public_key, fingerprint, kdf_algorithm, kdf_opslimit, kdf_memlimit, kdf_salt,
    private_key_nonce, private_key_ciphertext, recovery_nonce, recovery_ciphertext
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (user_id) DO UPDATE SET
    public_key = EXCLUDED.public_key,
    fingerprint = EXCLUDED.fingerprint,
    kdf_algorithm = EXCLUDED.kdf_algorithm,
    kdf_opslimit = EXCLUDED.kdf_opslimit,
    kdf_memlimit = EXCLUDED.kdf_memlimit,
    kdf_salt = EXCLUDED.kdf_salt,
    private_key_nonce = EXCLUDED.private_key_nonce,
    private_key_ciphertext = EXCLUDED.private_key_ciphertext,
    recovery_nonce = EXCLUDED.recovery_nonce,
    recovery_ciphertext = EXCLUDED.recovery_ciphertext,
    created_at = now()
RETURNING *;

-- name: GetCryptoProposal :one
SELECT * FROM crypto_proposals WHERE user_id = $1;

-- name: DeleteCryptoProposal :exec
DELETE FROM crypto_proposals WHERE user_id = $1;

-- name: DeletePendingIdentity :exec
DELETE FROM crypto_identities WHERE user_id = $1 AND status IN ('pending', 'rejected');

-- name: ListRenewalCandidates :many
SELECT sub.id, s.organization_id, sub.renewal_date, sub.billing_cycle, sub.custom_interval_days, sub.auto_renew
FROM subscriptions sub
JOIN services s ON s.id = sub.service_id
WHERE s.archived_at IS NULL;

-- name: ListKeyProposals :many
SELECT u.id AS user_id, u.display_name, u.email, p.public_key, p.fingerprint, p.created_at
FROM crypto_proposals p
JOIN users u ON u.id = p.user_id
WHERE u.organization_id = $1
ORDER BY p.created_at;

-- name: UpdatePassphraseBackup :one
UPDATE crypto_identities SET
    kdf_opslimit = sqlc.arg(kdf_opslimit),
    kdf_memlimit = sqlc.arg(kdf_memlimit),
    kdf_salt = sqlc.arg(kdf_salt),
    private_key_nonce = sqlc.arg(private_key_nonce),
    private_key_ciphertext = sqlc.arg(private_key_ciphertext)
WHERE user_id = sqlc.arg(user_id) AND status = 'approved' AND fingerprint = sqlc.arg(fingerprint)
RETURNING *;

-- name: ListPublicKeys :many
SELECT u.id AS user_id, u.display_name, u.email, u.status AS user_status,
       c.public_key, c.fingerprint, c.status AS key_status
FROM users u
JOIN crypto_identities c ON c.user_id = u.id
WHERE u.organization_id = $1
ORDER BY u.display_name, u.email;

-- name: CountVaults :one
SELECT count(*) FROM vaults WHERE organization_id = $1 AND archived_at IS NULL;

-- name: ListEnvelopeHolders :many
SELECT user_id FROM vault_key_envelopes WHERE vault_id = $1 AND key_version = $2;

-- name: CreateVault :one
INSERT INTO vaults (organization_id, name, description)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListVaults :many
SELECT * FROM vaults WHERE organization_id = $1 AND archived_at IS NULL ORDER BY name;

-- name: GetVault :one
SELECT * FROM vaults WHERE id = $1 AND organization_id = $2;

-- name: LockVault :one
SELECT * FROM vaults WHERE id = $1 AND organization_id = $2 FOR UPDATE;

-- name: MarkVaultInitialized :exec
UPDATE vaults SET initialized = true WHERE id = $1;

-- name: SetVaultRotationRequired :exec
UPDATE vaults SET rotation_required = $2 WHERE id = $1;

-- name: BumpVaultKeyVersion :one
UPDATE vaults SET key_version = key_version + 1, rotation_required = false
WHERE id = $1 AND key_version = $2
RETURNING *;

-- name: UpsertVaultMember :exec
INSERT INTO vault_members (vault_id, user_id, role) VALUES ($1, $2, $3)
ON CONFLICT (vault_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- name: DeleteVaultMember :exec
DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2;

-- name: ListVaultMembers :many
SELECT m.vault_id, m.user_id, m.role, u.display_name, u.email
FROM vault_members m
JOIN users u ON u.id = m.user_id
WHERE m.vault_id = $1
ORDER BY u.email;

-- name: GetVaultMember :one
SELECT vault_id, user_id, role FROM vault_members WHERE vault_id = $1 AND user_id = $2;

-- name: ListMembershipsForUser :many
SELECT vault_id, user_id, role FROM vault_members WHERE user_id = $1;

-- name: UpsertEnvelope :exec
INSERT INTO vault_key_envelopes (vault_id, user_id, key_version, recipient_fingerprint, ciphertext, created_by)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (vault_id, user_id, key_version) DO UPDATE SET
    recipient_fingerprint = EXCLUDED.recipient_fingerprint,
    ciphertext = EXCLUDED.ciphertext,
    created_by = EXCLUDED.created_by,
    created_at = now();

-- name: GetEnvelope :one
SELECT * FROM vault_key_envelopes WHERE vault_id = $1 AND user_id = $2 AND key_version = $3;

-- name: DeleteEnvelopesForUser :exec
DELETE FROM vault_key_envelopes WHERE user_id = $1;

-- name: DeleteEnvelopeForMember :exec
DELETE FROM vault_key_envelopes WHERE vault_id = $1 AND user_id = $2;

-- name: DeleteEnvelopesForVaultExceptVersion :exec
DELETE FROM vault_key_envelopes WHERE vault_id = $1 AND key_version <> $2;

-- name: DeleteStaleEnvelopesForUser :exec
DELETE FROM vault_key_envelopes
WHERE user_id = $1 AND recipient_fingerprint <> $2;

-- name: ListVaultIDsForUser :many
SELECT DISTINCT vault_id FROM vault_key_envelopes WHERE user_id = $1;

-- name: InsertVaultItem :one
INSERT INTO vault_items (id, vault_id, key_version, nonce, ciphertext, created_by, updated_by)
VALUES ($1, $2, $3, $4, $5, $6, $6)
RETURNING *;

-- name: RotateVaultItem :one
UPDATE vault_items
SET key_version = sqlc.arg(key_version), nonce = sqlc.arg(nonce), ciphertext = sqlc.arg(ciphertext),
    updated_by = sqlc.arg(updated_by), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND vault_id = sqlc.arg(vault_id) AND deleted_at IS NULL
  AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: GetVaultItem :one
SELECT * FROM vault_items WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL;

-- name: ListVaultItems :many
SELECT * FROM vault_items WHERE vault_id = $1 AND deleted_at IS NULL ORDER BY created_at;

-- name: DeleteVaultItems :exec
DELETE FROM vault_items WHERE vault_id = $1;

-- name: DeleteVaultItemsExcept :exec
DELETE FROM vault_items
WHERE vault_id = sqlc.arg(vault_id)
  AND NOT (id = ANY(sqlc.arg(keep_ids)::uuid[]));

-- name: UpdateVaultItem :one
UPDATE vault_items
SET nonce = sqlc.arg(nonce), ciphertext = sqlc.arg(ciphertext), key_version = sqlc.arg(key_version),
    updated_by = sqlc.arg(updated_by), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND vault_id = sqlc.arg(vault_id) AND deleted_at IS NULL
  AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: SoftDeleteVaultItem :exec
UPDATE vault_items SET deleted_at = now(), updated_by = $3, updated_at = now()
WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL;

-- name: GetCurrentEpoch :one
SELECT * FROM recovery_epochs
WHERE organization_id = $1 AND status IN ('active', 'degraded', 'spent');

-- name: GetNextEpoch :one
SELECT * FROM recovery_epochs
WHERE organization_id = $1 AND status IN ('pending', 'confirmed');

-- name: GetEpoch :one
SELECT * FROM recovery_epochs WHERE organization_id = $1 AND epoch = $2;

-- name: LockEpoch :one
SELECT * FROM recovery_epochs WHERE organization_id = $1 AND epoch = $2 FOR UPDATE;

-- name: MaxEpoch :one
SELECT COALESCE(MAX(epoch), 0)::integer FROM recovery_epochs WHERE organization_id = $1;

-- name: InsertEpoch :one
INSERT INTO recovery_epochs (
    organization_id, epoch, public_key, fingerprint, created_by, creator_public_key, creator_fingerprint
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: SetEpochStatus :exec
UPDATE recovery_epochs SET status = $3 WHERE organization_id = $1 AND epoch = $2;

-- name: RetireNextEpoch :exec
UPDATE recovery_epochs SET status = 'retired'
WHERE organization_id = $1 AND status IN ('pending', 'confirmed');

-- name: RetireCurrentEpoch :exec
UPDATE recovery_epochs SET status = 'retired'
WHERE organization_id = $1 AND status IN ('active', 'degraded', 'spent');

-- name: InsertCustodian :exec
INSERT INTO recovery_custodians (
    organization_id, epoch, share_index, user_id, fingerprint, share_nonce, share_ciphertext
) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListEpochCustodians :many
SELECT c.share_index, c.user_id, c.fingerprint, c.confirmed_at,
       u.display_name, u.email, u.status AS user_status
FROM recovery_custodians c
JOIN users u ON u.id = c.user_id
WHERE c.organization_id = $1 AND c.epoch = $2
ORDER BY c.share_index;

-- name: GetEpochCustodian :one
SELECT * FROM recovery_custodians
WHERE organization_id = $1 AND epoch = $2 AND user_id = $3;

-- name: ConfirmCustodian :execrows
UPDATE recovery_custodians SET confirmed_at = now()
WHERE organization_id = $1 AND epoch = $2 AND user_id = $3 AND confirmed_at IS NULL;

-- name: CountConfirmedCustodians :one
SELECT count(*)::integer FROM recovery_custodians
WHERE organization_id = $1 AND epoch = $2 AND confirmed_at IS NOT NULL;

-- name: ListEpochsInvolvingUser :many
SELECT e.epoch, e.status, (e.created_by = sqlc.arg(user_id))::boolean AS is_creator,
       EXISTS (
           SELECT 1 FROM recovery_custodians c
           WHERE c.organization_id = e.organization_id AND c.epoch = e.epoch AND c.user_id = sqlc.arg(user_id)
       )::boolean AS is_custodian
FROM recovery_epochs e
WHERE e.organization_id = sqlc.arg(organization_id) AND e.status <> 'retired';

-- name: UpsertRecoveryEnvelope :exec
INSERT INTO vault_recovery_envelopes (vault_id, key_version, epoch, ciphertext)
VALUES ($1, $2, $3, $4)
ON CONFLICT (vault_id, key_version) DO UPDATE SET epoch = EXCLUDED.epoch, ciphertext = EXCLUDED.ciphertext;

-- name: GetRecoveryEnvelope :one
SELECT * FROM vault_recovery_envelopes WHERE vault_id = $1 AND key_version = $2;

-- name: DeleteRecoveryEnvelopesExceptVersion :exec
DELETE FROM vault_recovery_envelopes WHERE vault_id = $1 AND key_version <> $2;

-- name: DeleteRecoveryEnvelopesForVault :exec
DELETE FROM vault_recovery_envelopes WHERE vault_id = $1;

-- name: DeleteOrgRecoveryEnvelopesExceptEpoch :exec
DELETE FROM vault_recovery_envelopes e
USING vaults v
WHERE v.id = e.vault_id AND v.organization_id = $1 AND e.epoch <> $2;

-- name: CountRecentChallenges :one
SELECT count(*)::integer FROM recovery_challenges
WHERE custodian_id = $1 AND created_at > $2;

-- name: InsertChallenge :exec
INSERT INTO recovery_challenges (id, organization_id, vault_id, epoch, custodian_id, digest, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ClaimChallenge :one
UPDATE recovery_challenges SET used_at = now()
WHERE id = $1 AND custodian_id = $2 AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: InsertRecoveryGrant :one
INSERT INTO recovery_grants (organization_id, vault_id, epoch, custodian_id, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetLiveRecoveryGrant :one
SELECT * FROM recovery_grants
WHERE custodian_id = $1 AND vault_id = $2 AND used_at IS NULL AND expires_at > now()
ORDER BY created_at DESC
LIMIT 1;

-- name: UseRecoveryGrant :execrows
UPDATE recovery_grants SET used_at = now()
WHERE id = $1 AND used_at IS NULL AND expires_at > now();

-- name: CreateService :one
INSERT INTO services (
    organization_id, name, category, url, description, unclear, logo, logo_bg, logo_fg, owner_id, notes, tags
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: UpdateService :one
UPDATE services SET
    name = $3,
    category = $4,
    url = $5,
    description = $6,
    unclear = $7,
    logo = $8,
    logo_bg = $9,
    logo_fg = $10,
    owner_id = $11,
    notes = $12,
    tags = $13,
    updated_at = now()
WHERE id = $1 AND organization_id = $2
RETURNING *;

-- name: GetService :one
SELECT * FROM services WHERE id = $1 AND organization_id = $2;

-- name: ListServicesForOrg :many
SELECT * FROM services WHERE organization_id = $1 ORDER BY name;

-- name: ArchiveService :one
UPDATE services SET archived_at = now(), updated_at = now()
WHERE id = $1 AND organization_id = $2 AND archived_at IS NULL
RETURNING *;

-- name: InsertGrant :exec
INSERT INTO service_grants (service_id, user_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteGrant :exec
DELETE FROM service_grants WHERE service_id = $1 AND user_id = $2;

-- name: ListGrantsForOrg :many
SELECT g.service_id, g.user_id
FROM service_grants g
JOIN services s ON s.id = g.service_id
WHERE s.organization_id = $1;

-- name: CreateAccount :one
INSERT INTO service_accounts (service_id, label, login_hint, card_label, notes, position)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateAccount :one
UPDATE service_accounts SET
    label = $2,
    login_hint = $3,
    card_label = $4,
    notes = $5,
    position = $6,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: GetAccount :one
SELECT a.*
FROM service_accounts a
JOIN services s ON s.id = a.service_id
WHERE a.id = $1 AND s.organization_id = $2;

-- name: DeleteAccount :exec
DELETE FROM service_accounts a USING services s
WHERE a.id = $1 AND a.service_id = s.id AND s.organization_id = $2;

-- name: ListAccountsForOrg :many
SELECT a.id, a.service_id, a.label, a.login_hint, a.card_label, a.notes,
       a.vault_id, a.vault_item_id, a.position, a.created_at, a.updated_at
FROM service_accounts a
JOIN services s ON s.id = a.service_id
WHERE s.organization_id = $1
ORDER BY a.position, a.created_at;

-- name: LinkAccountVaultItem :exec
UPDATE service_accounts a SET vault_id = $3, vault_item_id = $4, updated_at = now()
FROM services s
WHERE a.id = $1 AND a.service_id = s.id AND s.organization_id = $2;

-- name: CreateSubscription :one
INSERT INTO subscriptions (
    service_id, account_id, payment_method_id, name, billing_cycle, custom_interval_days,
    renewal_date, cost_minor, currency, auto_renew
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: UpdateSubscription :one
UPDATE subscriptions SET
    payment_method_id = $2,
    name = $3,
    billing_cycle = $4,
    custom_interval_days = $5,
    renewal_date = $6,
    cost_minor = $7,
    currency = $8,
    auto_renew = $9,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: GetSubscription :one
SELECT sub.*
FROM subscriptions sub
JOIN services s ON s.id = sub.service_id
WHERE sub.id = $1 AND s.organization_id = $2;

-- name: ListSubscriptionsForOrg :many
SELECT sub.id, sub.service_id, sub.account_id, sub.payment_method_id, sub.name, sub.billing_cycle,
       sub.custom_interval_days, sub.renewal_date, sub.cost_minor, sub.currency, sub.auto_renew,
       sub.created_at, sub.updated_at
FROM subscriptions sub
JOIN services s ON s.id = sub.service_id
WHERE s.organization_id = $1
ORDER BY sub.renewal_date;

-- name: InsertPayment :one
INSERT INTO payments (subscription_id, paid_on, amount_minor, currency, note)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: ListPaymentsForSubscription :many
SELECT * FROM payments WHERE subscription_id = $1 ORDER BY paid_on DESC;

-- name: InsertPaymentMethod :one
INSERT INTO payment_methods (organization_id, nickname, issuer, last4, exp_month, exp_year)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListPaymentMethods :many
SELECT * FROM payment_methods WHERE organization_id = $1 ORDER BY nickname;

-- name: DeletePaymentMethod :exec
DELETE FROM payment_methods WHERE id = $1 AND organization_id = $2;

-- name: AdvanceRenewalDate :execrows
-- Moves an auto-renewing subscription to its next renewal; the old date
-- guards against a concurrent edit.
UPDATE subscriptions SET renewal_date = sqlc.arg(next_date), updated_at = now()
WHERE id = sqlc.arg(id) AND renewal_date = sqlc.arg(previous_date) AND auto_renew;

-- name: InsertRenewalAlert :exec
INSERT INTO renewal_alerts (organization_id, subscription_id, days_before, due_on)
VALUES ($1, $2, $3, $4)
ON CONFLICT (subscription_id, days_before, due_on) DO NOTHING;

-- name: ListRenewalAlerts :many
SELECT a.id, a.subscription_id, a.days_before, a.due_on, a.created_at,
       sub.service_id, sub.name, sub.currency, sub.cost_minor
FROM renewal_alerts a
JOIN subscriptions sub ON sub.id = a.subscription_id
WHERE a.organization_id = $1
ORDER BY a.due_on, a.days_before;

-- name: InsertCredentialFlag :one
INSERT INTO credential_flags (organization_id, vault_item_id, service_account_id, reason)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListOpenCredentialFlags :many
SELECT * FROM credential_flags
WHERE organization_id = $1 AND resolved_at IS NULL
ORDER BY flagged_at DESC;

-- name: ResolveCredentialFlag :one
UPDATE credential_flags SET resolved_at = now()
WHERE id = $1 AND organization_id = $2 AND resolved_at IS NULL
RETURNING *;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (organization_id, actor_id, action, target_type, target_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAuditEvents :many
SELECT * FROM audit_events
WHERE organization_id = $1
ORDER BY id DESC
LIMIT $2;

-- name: CreateAPIToken :one
INSERT INTO api_tokens (organization_id, user_id, name, token_hash, can_write, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, name, can_write, created_at, expires_at, last_used_at, revoked_at;

-- name: CountLiveAPITokens :one
SELECT count(*) FROM api_tokens
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: ListAPITokens :many
SELECT t.id, t.user_id, u.display_name, u.email, t.name, t.can_write, t.created_at, t.expires_at, t.last_used_at, t.revoked_at
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.organization_id = sqlc.arg(organization_id) AND (sqlc.arg(all_users)::boolean OR t.user_id = sqlc.arg(user_id))
ORDER BY t.created_at DESC;

-- name: RevokeAPIToken :one
UPDATE api_tokens SET revoked_at = now()
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND revoked_at IS NULL
  AND (sqlc.arg(any_user)::boolean OR user_id = sqlc.arg(user_id))
RETURNING id, user_id;

-- name: RevokeAPITokensForUser :exec
UPDATE api_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: GetActiveAPIToken :one
SELECT t.id, t.user_id, t.can_write, u.organization_id, u.email, u.display_name, u.role, u.status
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.expires_at > now() AND u.status = 'active';

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = now()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: InsertVaultFile :one
INSERT INTO vault_files (id, vault_id, account_id, size, content, created_by)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, size, created_at;

-- name: CountAccountFiles :one
SELECT count(*) FROM vault_files WHERE account_id = $1;

-- name: VaultFileBytes :one
SELECT coalesce(sum(size), 0)::bigint FROM vault_files WHERE vault_id = $1;

-- name: GetVaultFileMeta :one
SELECT id, vault_id, account_id, size FROM vault_files WHERE id = $1 AND vault_id = $2;

-- name: GetVaultFileContent :one
SELECT content FROM vault_files WHERE id = $1 AND vault_id = $2;

-- name: DeleteVaultFile :execrows
DELETE FROM vault_files WHERE id = $1 AND vault_id = $2;
