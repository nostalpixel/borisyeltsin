package httpserver

import (
	"bytes"
	"context"
	"net/http"
	"sort"

	"github.com/google/uuid"
	"github.com/nostalpixel/borisyeltsin/internal/authz"
	"github.com/nostalpixel/borisyeltsin/internal/db"
)

// Every write that depends on a vault's key version, item versions, members or
// envelopes runs under the vault row lock:
//
//	BEGIN
//	SET LOCAL lock_timeout = '5s'         -- waiting longer returns 503 vault_busy
//	SELECT ... FROM vaults ... FOR UPDATE  -- one row per vault, IDs in sorted order
//	fn(q, vault)                           -- checks and writes share the transaction
//	COMMIT                                 -- any error rolls back writes and audit rows
//
// Paths that touch several vaults (user revocation, key replacement) lock them
// in sorted ID order, so two writers never wait on each other in opposite order.

// withVaultLock runs fn in a transaction that holds the lock on one vault.
func (s *Server) withVaultLock(ctx context.Context, org, vaultID uuid.UUID, fn func(q *db.Queries, vault db.Vault) error) error {
	return s.inTx(ctx, func(q *db.Queries) error {
		vaults, err := lockVaults(ctx, q, org, []uuid.UUID{vaultID})
		if err != nil {
			return err
		}
		return fn(q, vaults[0])
	})
}

// inTx runs fn in a transaction with the vault lock timeout set.
func (s *Server) inTx(ctx context.Context, fn func(q *db.Queries) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '5s'"); err != nil {
		return err
	}
	if err := fn(s.Q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// lockVaults locks each vault of the organization in sorted ID order.
func lockVaults(ctx context.Context, q *db.Queries, org uuid.UUID, ids []uuid.UUID) ([]db.Vault, error) {
	sorted := append([]uuid.UUID(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][:], sorted[j][:]) < 0 })
	out := make([]db.Vault, 0, len(sorted))
	for i, id := range sorted {
		if i > 0 && id == sorted[i-1] {
			continue
		}
		vault, err := q.LockVault(ctx, db.LockVaultParams{ID: id, OrganizationID: org})
		if isNoRows(err) {
			return nil, errStatus(http.StatusNotFound, "not_found")
		}
		if err != nil {
			return nil, err
		}
		out = append(out, vault)
	}
	return out, nil
}

// holdsKey reports whether the user has an envelope for the vault's current key.
func holdsKey(ctx context.Context, q *db.Queries, vault db.Vault, userID uuid.UUID) bool {
	env, err := q.GetEnvelope(ctx, db.GetEnvelopeParams{VaultID: vault.ID, UserID: userID, KeyVersion: vault.KeyVersion})
	return err == nil && len(env.Ciphertext) > 0
}

// requireKeyOwner allows vault owners who hold the current key. The server
// cannot check that a client knows the vault key, but it can check that the
// caller was given an envelope for it. App admins get no exception.
func requireKeyOwner(ctx context.Context, q *db.Queries, p Principal, vault db.Vault) error {
	member, err := q.GetVaultMember(ctx, db.GetVaultMemberParams{VaultID: vault.ID, UserID: p.UserID})
	if err != nil || !authz.CanReadVault(member.Role) {
		return errStatus(http.StatusNotFound, "not_found")
	}
	if !authz.CanAdminVault(member.Role) {
		return errStatus(http.StatusForbidden, "forbidden")
	}
	if !holdsKey(ctx, q, vault, p.UserID) {
		return errStatus(http.StatusForbidden, "not_key_holder")
	}
	return nil
}

// otherOwners counts owners of the vault other than userID.
func otherOwners(ctx context.Context, q *db.Queries, vaultID, userID uuid.UUID) (int, error) {
	members, err := q.ListVaultMembers(ctx, vaultID)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, member := range members {
		if member.UserID != userID && member.Role == "owner" {
			count++
		}
	}
	return count, nil
}
