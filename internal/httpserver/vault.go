package httpserver

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/nostalpixel/borisyeltsin/internal/authz"
	"github.com/nostalpixel/borisyeltsin/internal/db"
)

func (s *Server) memberVault(ctx context.Context, p Principal, vaultID uuid.UUID) (db.Vault, db.VaultMember, error) {
	vault, err := s.Q.GetVault(ctx, db.GetVaultParams{ID: vaultID, OrganizationID: p.OrgID})
	if err != nil {
		return db.Vault{}, db.VaultMember{}, errStatus(http.StatusNotFound, "not_found")
	}
	member, err := s.Q.GetVaultMember(ctx, db.GetVaultMemberParams{VaultID: vaultID, UserID: p.UserID})
	if err != nil || !authz.CanReadVault(member.Role) {
		return db.Vault{}, db.VaultMember{}, errStatus(http.StatusNotFound, "not_found")
	}
	return vault, member, nil
}

func (s *Server) metaVault(ctx context.Context, p Principal, vaultID uuid.UUID) (db.Vault, error) {
	vault, err := s.Q.GetVault(ctx, db.GetVaultParams{ID: vaultID, OrganizationID: p.OrgID})
	if err != nil {
		return db.Vault{}, errStatus(http.StatusNotFound, "not_found")
	}
	if p.Role == "admin" {
		return vault, nil
	}
	_, _, err = s.memberVault(ctx, p, vaultID)
	if err != nil {
		return db.Vault{}, err
	}
	return vault, nil
}

func (s *Server) listVaults(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	rows, err := s.Q.ListVaults(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	memberships, err := s.Q.ListMembershipsForUser(r.Context(), p.UserID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	mine := map[uuid.UUID]string{}
	for _, member := range memberships {
		mine[member.VaultID] = member.Role
	}
	out := []map[string]any{}
	for _, row := range rows {
		role, ok := mine[row.ID]
		if !ok && p.Role != "admin" {
			continue
		}
		out = append(out, map[string]any{
			"id": row.ID, "name": row.Name, "description": row.Description,
			"key_version": row.KeyVersion, "rotation_required": row.RotationRequired, "role": role,
			"initialized": row.Initialized,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"vaults": out})
}

func (s *Server) createVault(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if p.Role == "readonly" {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	body.Name = clip(body.Name, 80)
	body.Description = clip(body.Description, 500)
	if body.Name == "" {
		s.fail(w, http.StatusBadRequest, "bad_vault")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	defer tx.Rollback(r.Context())
	q := s.Q.WithTx(tx)
	row, err := q.CreateVault(r.Context(), db.CreateVaultParams{OrganizationID: p.OrgID, Name: body.Name, Description: body.Description})
	if err != nil {
		s.sendError(w, err)
		return
	}
	if err := q.UpsertVaultMember(r.Context(), db.UpsertVaultMemberParams{VaultID: row.ID, UserID: p.UserID, Role: "owner"}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "vault_created", "vault", row.ID.String(), nil)
	s.writeJSON(w, http.StatusCreated, map[string]any{"id": row.ID, "name": row.Name, "key_version": row.KeyVersion})
}

func (s *Server) getVault(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	id, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	vault, err := s.metaVault(r.Context(), p, id)
	if err != nil {
		s.sendError(w, err)
		return
	}
	members, err := s.Q.ListVaultMembers(r.Context(), id)
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"id": vault.ID, "name": vault.Name, "description": vault.Description,
		"key_version": vault.KeyVersion, "rotation_required": vault.RotationRequired, "members": members,
	})
}

func (s *Server) approvedKey(ctx context.Context, org, userID uuid.UUID) (db.CryptoIdentity, error) {
	return approvedKeyQ(ctx, s.Q, org, userID)
}

func approvedKeyQ(ctx context.Context, q *db.Queries, org, userID uuid.UUID) (db.CryptoIdentity, error) {
	user, err := q.GetUser(ctx, db.GetUserParams{ID: userID, OrganizationID: org})
	if err != nil || user.Status != "active" {
		return db.CryptoIdentity{}, errStatus(http.StatusBadRequest, "bad_recipient")
	}
	ident, err := q.GetCryptoIdentity(ctx, userID)
	if err != nil || ident.Status != "approved" {
		return db.CryptoIdentity{}, errStatus(http.StatusBadRequest, "key_not_approved")
	}
	return ident, nil
}

func (s *Server) addVaultMember(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		UserID uuid.UUID `json:"user_id"`
		Role   string    `json:"role"`
	}
	if !s.decode(w, r, &body) || !authz.ValidVaultRole(body.Role) {
		s.fail(w, http.StatusBadRequest, "bad_role")
		return
	}
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		if err := requireKeyOwner(r.Context(), q, p, vault); err != nil {
			return err
		}
		user, err := q.GetUser(r.Context(), db.GetUserParams{ID: body.UserID, OrganizationID: p.OrgID})
		if err != nil || user.Status != "active" {
			return errStatus(http.StatusBadRequest, "bad_member")
		}
		current, err := q.GetVaultMember(r.Context(), db.GetVaultMemberParams{VaultID: vault.ID, UserID: body.UserID})
		if err == nil && current.Role == "owner" && body.Role != "owner" {
			others, err := otherOwners(r.Context(), q, vault.ID, body.UserID)
			if err != nil {
				return err
			}
			if others == 0 {
				return errStatus(http.StatusConflict, "last_vault_owner")
			}
		}
		if err := q.UpsertVaultMember(r.Context(), db.UpsertVaultMemberParams{VaultID: vault.ID, UserID: body.UserID, Role: body.Role}); err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "vault_member_added", "vault", vault.ID.String(), map[string]string{"user_id": body.UserID.String(), "role": body.Role})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) removeVaultMember(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	userID, err := pathID(r, "userID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		if err := requireKeyOwner(r.Context(), q, p, vault); err != nil {
			return err
		}
		target, err := q.GetVaultMember(r.Context(), db.GetVaultMemberParams{VaultID: vaultID, UserID: userID})
		if err != nil {
			return errStatus(http.StatusNotFound, "not_found")
		}
		if target.Role == "owner" {
			others, err := otherOwners(r.Context(), q, vaultID, userID)
			if err != nil {
				return err
			}
			if others == 0 {
				return errStatus(http.StatusConflict, "last_vault_owner")
			}
		}
		if err := q.DeleteVaultMember(r.Context(), db.DeleteVaultMemberParams{VaultID: vaultID, UserID: userID}); err != nil {
			return err
		}
		if err := q.DeleteEnvelopeForMember(r.Context(), db.DeleteEnvelopeForMemberParams{VaultID: vaultID, UserID: userID}); err != nil {
			return err
		}
		if err := q.SetVaultRotationRequired(r.Context(), db.SetVaultRotationRequiredParams{ID: vaultID, RotationRequired: true}); err != nil {
			return err
		}
		if _, err := q.InsertCredentialFlag(r.Context(), db.InsertCredentialFlagParams{OrganizationID: p.OrgID, Reason: "member_removed"}); err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "vault_member_removed", "vault", vaultID.String(), map[string]string{"user_id": userID.String()})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// staleKey rejects writes made for a key version that is no longer current.
func staleKey(expected int32, vault db.Vault) error {
	if expected != vault.KeyVersion {
		return errStatus(http.StatusConflict, "stale_key")
	}
	return nil
}

func (s *Server) putEnvelope(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		UserID             uuid.UUID `json:"user_id"`
		Fingerprint        string    `json:"fingerprint"`
		Ciphertext         string    `json:"ciphertext"`
		ExpectedKeyVersion int32     `json:"expected_key_version"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	ciphertext, err := decodeB64(body.Ciphertext, 0, 48, 8192)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_envelope")
		return
	}
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		member, err := q.GetVaultMember(r.Context(), db.GetVaultMemberParams{VaultID: vaultID, UserID: p.UserID})
		if err != nil || !authz.CanReadVault(member.Role) {
			return errStatus(http.StatusNotFound, "not_found")
		}
		if !authz.CanAdminVault(member.Role) {
			return errStatus(http.StatusForbidden, "forbidden")
		}
		if err := staleKey(body.ExpectedKeyVersion, vault); err != nil {
			return err
		}
		if _, err := q.GetVaultMember(r.Context(), db.GetVaultMemberParams{VaultID: vaultID, UserID: body.UserID}); err != nil {
			return errStatus(http.StatusBadRequest, "bad_recipient")
		}
		ident, err := approvedKeyQ(r.Context(), q, p.OrgID, body.UserID)
		if err != nil {
			return err
		}
		if body.Fingerprint != ident.Fingerprint {
			return errStatus(http.StatusBadRequest, "fingerprint_mismatch")
		}
		// The first envelope of a vault is the owner's own and happens once.
		// After that only a current key holder can share the key.
		if !vault.Initialized {
			if body.UserID != p.UserID {
				return errStatus(http.StatusForbidden, "owner_envelope_first")
			}
			if err := q.MarkVaultInitialized(r.Context(), vaultID); err != nil {
				return err
			}
		} else if !holdsKey(r.Context(), q, vault, p.UserID) {
			return errStatus(http.StatusForbidden, "not_key_holder")
		}
		if err := q.UpsertEnvelope(r.Context(), db.UpsertEnvelopeParams{
			VaultID: vaultID, UserID: body.UserID, KeyVersion: vault.KeyVersion,
			RecipientFingerprint: ident.Fingerprint, Ciphertext: ciphertext, CreatedBy: p.UserID,
		}); err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "envelope_written", "vault", vaultID.String(), map[string]string{"user_id": body.UserID.String()})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getEnvelope(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	vault, _, err := s.memberVault(r.Context(), p, vaultID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	env, err := s.Q.GetEnvelope(r.Context(), db.GetEnvelopeParams{VaultID: vaultID, UserID: p.UserID, KeyVersion: vault.KeyVersion})
	if err != nil {
		// The caller is a member, so saying "no key yet" leaks nothing.
		s.fail(w, http.StatusNotFound, "no_access")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"vault_id": vaultID, "key_version": env.KeyVersion,
		"fingerprint": env.RecipientFingerprint, "ciphertext": encodeB64(env.Ciphertext),
	})
}

// requireItemAccess checks membership, write role and a current envelope.
func requireItemAccess(ctx context.Context, q *db.Queries, p Principal, vault db.Vault, write bool) error {
	member, err := q.GetVaultMember(ctx, db.GetVaultMemberParams{VaultID: vault.ID, UserID: p.UserID})
	if err != nil || !authz.CanReadVault(member.Role) {
		return errStatus(http.StatusNotFound, "not_found")
	}
	if write && !authz.CanWriteVault(member.Role) {
		return errStatus(http.StatusForbidden, "forbidden")
	}
	if !holdsKey(ctx, q, vault, p.UserID) {
		return errStatus(http.StatusForbidden, "vault_locked")
	}
	return nil
}

func (s *Server) listItems(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	vault, err := s.Q.GetVault(r.Context(), db.GetVaultParams{ID: vaultID, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if err := requireItemAccess(r.Context(), s.Q, p, vault, false); err != nil {
		s.sendError(w, err)
		return
	}
	rows, err := s.Q.ListVaultItems(r.Context(), vaultID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	out := []map[string]any{}
	for _, row := range rows {
		if row.KeyVersion != vault.KeyVersion {
			continue
		}
		out = append(out, map[string]any{
			"id": row.ID, "key_version": row.KeyVersion, "version": row.Version,
			"nonce": encodeB64(row.Nonce), "ciphertext": encodeB64(row.Ciphertext),
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"key_version": vault.KeyVersion, "items": out})
}

func (s *Server) createItem(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		ID                 uuid.UUID `json:"id"`
		Nonce              string    `json:"nonce"`
		Ciphertext         string    `json:"ciphertext"`
		ExpectedKeyVersion int32     `json:"expected_key_version"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	if body.ID == uuid.Nil {
		body.ID = uuid.New()
	}
	nonce, ct, err := itemCipher(body.Nonce, body.Ciphertext)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_item")
		return
	}
	var row db.VaultItem
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		if err := requireItemAccess(r.Context(), q, p, vault, true); err != nil {
			return err
		}
		if err := staleKey(body.ExpectedKeyVersion, vault); err != nil {
			return err
		}
		org, err := q.GetOrganization(r.Context(), p.OrgID)
		if err != nil || !org.RecoveryReady {
			return errStatus(http.StatusConflict, "recovery_not_ready")
		}
		if _, err := q.GetRecoveryEnvelope(r.Context(), db.GetRecoveryEnvelopeParams{VaultID: vaultID, KeyVersion: vault.KeyVersion}); err != nil {
			return errStatus(http.StatusConflict, "recovery_envelope_missing")
		}
		row, err = q.InsertVaultItem(r.Context(), db.InsertVaultItemParams{
			ID: body.ID, VaultID: vaultID, KeyVersion: vault.KeyVersion, Nonce: nonce, Ciphertext: ct, CreatedBy: p.UserID,
		})
		if err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "vault_item_created", "vault_item", row.ID.String(), nil)
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"id": row.ID, "version": row.Version})
}

func itemCipher(nonceRaw, ctRaw string) ([]byte, []byte, error) {
	nonce, err := decodeB64(nonceRaw, 24, 0, 0)
	if err != nil {
		return nil, nil, err
	}
	ct, err := decodeB64(ctRaw, 0, 17, 262144)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

func (s *Server) updateItem(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	itemID, err := pathID(r, "itemID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		Nonce              string `json:"nonce"`
		Ciphertext         string `json:"ciphertext"`
		ExpectedKeyVersion int32  `json:"expected_key_version"`
		Version            int32  `json:"version"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	nonce, ct, err := itemCipher(body.Nonce, body.Ciphertext)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_item")
		return
	}
	var row db.VaultItem
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		if err := requireItemAccess(r.Context(), q, p, vault, true); err != nil {
			return err
		}
		if err := staleKey(body.ExpectedKeyVersion, vault); err != nil {
			return err
		}
		row, err = q.UpdateVaultItem(r.Context(), db.UpdateVaultItemParams{
			ID: itemID, VaultID: vaultID, Nonce: nonce, Ciphertext: ct, KeyVersion: vault.KeyVersion,
			UpdatedBy: p.UserID, ExpectedVersion: body.Version,
		})
		if isNoRows(err) {
			if _, getErr := q.GetVaultItem(r.Context(), db.GetVaultItemParams{ID: itemID, VaultID: vaultID}); getErr == nil {
				return errStatus(http.StatusConflict, "item_conflict")
			}
			return errStatus(http.StatusNotFound, "not_found")
		}
		if err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "vault_item_updated", "vault_item", itemID.String(), nil)
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": row.Version})
}

func (s *Server) deleteItem(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	itemID, err := pathID(r, "itemID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		if err := requireItemAccess(r.Context(), q, p, vault, true); err != nil {
			return err
		}
		if err := q.SoftDeleteVaultItem(r.Context(), db.SoftDeleteVaultItemParams{ID: itemID, VaultID: vaultID, UpdatedBy: p.UserID}); err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "vault_item_deleted", "vault_item", itemID.String(), nil)
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type rotationBody struct {
	ExpectedVersion int32 `json:"expected_key_version"`
	Items           []struct {
		ID         uuid.UUID `json:"id"`
		Version    int32     `json:"version"`
		Nonce      string    `json:"nonce"`
		Ciphertext string    `json:"ciphertext"`
	} `json:"items"`
	Envelopes []struct {
		UserID      uuid.UUID `json:"user_id"`
		Fingerprint string    `json:"fingerprint"`
		Ciphertext  string    `json:"ciphertext"`
	} `json:"envelopes"`
	Recovery struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	} `json:"recovery"`
}

type preparedItem struct {
	id      uuid.UUID
	version int32
	nonce   []byte
	ct      []byte
}

type preparedRotation struct {
	items    []preparedItem
	envs     [][]byte
	recNonce []byte
	recCT    []byte
}

// validateRotation checks a rotation against the locked vault state:
//
//	key version   body.expected == vault.key_version            else 409 version_conflict
//	items         same id set as the live items                  else 409 items_changed
//	              same version per item                          else 409 item_conflict
//	envelopes     exactly one per member, approved fingerprint   else 400
//	recovery      org recovery_ready, 24-byte nonce, 48-byte box else 409 / 400
func validateRotation(ctx context.Context, q *db.Queries, org uuid.UUID, vault db.Vault, body rotationBody) (preparedRotation, error) {
	var out preparedRotation
	if body.ExpectedVersion != vault.KeyVersion {
		return out, errStatus(http.StatusConflict, "version_conflict")
	}
	live, err := q.ListVaultItems(ctx, vault.ID)
	if err != nil {
		return out, err
	}
	liveVersion := map[uuid.UUID]int32{}
	for _, item := range live {
		liveVersion[item.ID] = item.Version
	}
	if len(body.Items) != len(live) {
		return out, errStatus(http.StatusConflict, "items_changed")
	}
	seen := map[uuid.UUID]bool{}
	for _, item := range body.Items {
		version, ok := liveVersion[item.ID]
		if !ok || seen[item.ID] {
			return out, errStatus(http.StatusConflict, "items_changed")
		}
		seen[item.ID] = true
		if version != item.Version {
			return out, errStatus(http.StatusConflict, "item_conflict")
		}
		nonce, ct, err := itemCipher(item.Nonce, item.Ciphertext)
		if err != nil {
			return out, errStatus(http.StatusBadRequest, "bad_item")
		}
		out.items = append(out.items, preparedItem{id: item.ID, version: item.Version, nonce: nonce, ct: ct})
	}
	members, err := q.ListVaultMembers(ctx, vault.ID)
	if err != nil {
		return out, err
	}
	if len(body.Envelopes) != len(members) {
		return out, errStatus(http.StatusBadRequest, "envelope_set")
	}
	wanted := map[uuid.UUID]bool{}
	for _, member := range members {
		wanted[member.UserID] = true
	}
	envSeen := map[uuid.UUID]bool{}
	for _, env := range body.Envelopes {
		if envSeen[env.UserID] || !wanted[env.UserID] {
			return out, errStatus(http.StatusBadRequest, "envelope_set")
		}
		envSeen[env.UserID] = true
		ident, err := approvedKeyQ(ctx, q, org, env.UserID)
		if err != nil || env.Fingerprint != ident.Fingerprint {
			return out, errStatus(http.StatusBadRequest, "fingerprint_mismatch")
		}
		ct, err := decodeB64(env.Ciphertext, 0, 48, 8192)
		if err != nil {
			return out, errStatus(http.StatusBadRequest, "bad_envelope")
		}
		out.envs = append(out.envs, ct)
	}
	orgRow, err := q.GetOrganization(ctx, org)
	if err != nil || !orgRow.RecoveryReady {
		return out, errStatus(http.StatusConflict, "recovery_not_ready")
	}
	out.recNonce, out.recCT, err = recoveryBox(body.Recovery.Nonce, body.Recovery.Ciphertext)
	return out, err
}

// recoveryBox decodes a secretbox of a 32-byte vault key: 24-byte nonce, 48-byte box.
func recoveryBox(nonceRaw, ctRaw string) ([]byte, []byte, error) {
	nonce, err := decodeB64(nonceRaw, 24, 0, 0)
	if err != nil {
		return nil, nil, errStatus(http.StatusBadRequest, "bad_envelope")
	}
	ct, err := decodeB64(ctRaw, 48, 0, 0)
	if err != nil {
		return nil, nil, errStatus(http.StatusBadRequest, "bad_envelope")
	}
	return nonce, ct, nil
}

func (s *Server) rotateVault(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body rotationBody
	if !s.decode(w, r, &body) {
		return
	}
	next := body.ExpectedVersion + 1
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		if err := requireKeyOwner(r.Context(), q, p, vault); err != nil {
			return err
		}
		prepared, err := validateRotation(r.Context(), q, p.OrgID, vault, body)
		if err != nil {
			return err
		}
		keep := make([]uuid.UUID, 0, len(prepared.items))
		for _, item := range prepared.items {
			// Update in place so service_accounts.vault_item_id survives.
			if _, err := q.RotateVaultItem(r.Context(), db.RotateVaultItemParams{
				ID: item.id, VaultID: vaultID, KeyVersion: next, Nonce: item.nonce, Ciphertext: item.ct,
				UpdatedBy: p.UserID, ExpectedVersion: item.version,
			}); isNoRows(err) {
				return errStatus(http.StatusConflict, "item_conflict")
			} else if err != nil {
				return err
			}
			keep = append(keep, item.id)
		}
		// Soft-deleted rows were encrypted under the old key; drop them.
		if len(keep) == 0 {
			if err := q.DeleteVaultItems(r.Context(), vaultID); err != nil {
				return err
			}
		} else if err := q.DeleteVaultItemsExcept(r.Context(), db.DeleteVaultItemsExceptParams{VaultID: vaultID, KeepIds: keep}); err != nil {
			return err
		}
		if err := q.DeleteEnvelopesForVaultExceptVersion(r.Context(), db.DeleteEnvelopesForVaultExceptVersionParams{VaultID: vaultID, KeyVersion: next}); err != nil {
			return err
		}
		for i, env := range body.Envelopes {
			if err := q.UpsertEnvelope(r.Context(), db.UpsertEnvelopeParams{
				VaultID: vaultID, UserID: env.UserID, KeyVersion: next, RecipientFingerprint: env.Fingerprint,
				Ciphertext: prepared.envs[i], CreatedBy: p.UserID,
			}); err != nil {
				return err
			}
		}
		if err := q.UpsertRecoveryEnvelope(r.Context(), db.UpsertRecoveryEnvelopeParams{
			VaultID: vaultID, KeyVersion: next, Nonce: prepared.recNonce, Ciphertext: prepared.recCT,
		}); err != nil {
			return err
		}
		if err := q.DeleteRecoveryEnvelopesExceptVersion(r.Context(), db.DeleteRecoveryEnvelopesExceptVersionParams{VaultID: vaultID, KeyVersion: next}); err != nil {
			return err
		}
		if _, err := q.BumpVaultKeyVersion(r.Context(), db.BumpVaultKeyVersionParams{ID: vaultID, KeyVersion: body.ExpectedVersion}); err != nil {
			return errStatus(http.StatusConflict, "version_conflict")
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "vault_rotated", "vault", vaultID.String(), nil)
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"key_version": next})
}

func (s *Server) putRecovery(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		Custodians []struct {
			UserID      uuid.UUID `json:"user_id"`
			ShareIndex  int16     `json:"share_index"`
			Fingerprint string    `json:"fingerprint"`
			Ciphertext  string    `json:"share_ciphertext"`
		} `json:"custodians"`
	}
	if !s.decode(w, r, &body) || len(body.Custodians) != 2 {
		s.fail(w, http.StatusBadRequest, "bad_recovery")
		return
	}
	if body.Custodians[0].UserID == body.Custodians[1].UserID {
		s.fail(w, http.StatusBadRequest, "bad_recovery")
		return
	}
	indexes := map[int16]bool{}
	for _, custodian := range body.Custodians {
		ident, err := s.approvedKey(r.Context(), p.OrgID, custodian.UserID)
		if err != nil || ident.Fingerprint != custodian.Fingerprint {
			s.fail(w, http.StatusBadRequest, "fingerprint_mismatch")
			return
		}
		if custodian.ShareIndex != 1 && custodian.ShareIndex != 2 {
			s.fail(w, http.StatusBadRequest, "bad_recovery")
			return
		}
		indexes[custodian.ShareIndex] = true
		if _, err := decodeB64(custodian.Ciphertext, 0, 48, 8192); err != nil {
			s.fail(w, http.StatusBadRequest, "bad_recovery")
			return
		}
	}
	if !indexes[1] || !indexes[2] {
		s.fail(w, http.StatusBadRequest, "bad_recovery")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	defer tx.Rollback(r.Context())
	q := s.Q.WithTx(tx)
	if err := q.DeleteCustodians(r.Context(), p.OrgID); err != nil {
		s.sendError(w, err)
		return
	}
	for _, custodian := range body.Custodians {
		raw, _ := decodeB64(custodian.Ciphertext, 0, 48, 8192)
		if err := q.InsertCustodian(r.Context(), db.InsertCustodianParams{
			OrganizationID: p.OrgID, UserID: custodian.UserID, ShareIndex: custodian.ShareIndex,
			ShareCiphertext: raw, Fingerprint: custodian.Fingerprint,
		}); err != nil {
			s.sendError(w, err)
			return
		}
	}
	if err := q.SetRecoveryReady(r.Context(), db.SetRecoveryReadyParams{ID: p.OrgID, RecoveryReady: true}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "recovery_enrolled", "organization", p.OrgID.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]bool{"recovery_ready": true})
}

func (s *Server) getRecovery(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	rows, err := s.Q.ListCustodians(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	org, err := s.Q.GetOrganization(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	out := []map[string]any{}
	for _, row := range rows {
		out = append(out, map[string]any{
			"user_id": row.UserID, "display_name": row.DisplayName, "email": row.Email,
			"share_index": row.ShareIndex, "fingerprint": row.Fingerprint,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"recovery_ready": org.RecoveryReady, "custodians": out})
}

func (s *Server) getRecoveryShare(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	row, err := s.Q.GetCustodianShare(r.Context(), db.GetCustodianShareParams{OrganizationID: p.OrgID, UserID: p.UserID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"share_index": row.ShareIndex, "fingerprint": row.Fingerprint, "share_ciphertext": encodeB64(row.ShareCiphertext),
	})
}

func (s *Server) putRecoveryEnvelope(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		Nonce              string `json:"nonce"`
		Ciphertext         string `json:"ciphertext"`
		ExpectedKeyVersion int32  `json:"expected_key_version"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	nonce, ct, err := recoveryBox(body.Nonce, body.Ciphertext)
	if err != nil {
		s.sendError(w, err)
		return
	}
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		if err := requireKeyOwner(r.Context(), q, p, vault); err != nil {
			return err
		}
		if err := staleKey(body.ExpectedKeyVersion, vault); err != nil {
			return err
		}
		if err := q.UpsertRecoveryEnvelope(r.Context(), db.UpsertRecoveryEnvelopeParams{
			VaultID: vaultID, KeyVersion: vault.KeyVersion, Nonce: nonce, Ciphertext: ct,
		}); err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "recovery_envelope_written", "vault", vaultID.String(), nil)
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getRecoveryEnvelope(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	vault, err := s.Q.GetVault(r.Context(), db.GetVaultParams{ID: vaultID, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	_, memberErr := s.Q.GetVaultMember(r.Context(), db.GetVaultMemberParams{VaultID: vaultID, UserID: p.UserID})
	_, shareErr := s.Q.GetCustodianShare(r.Context(), db.GetCustodianShareParams{OrganizationID: p.OrgID, UserID: p.UserID})
	if memberErr != nil && shareErr != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	row, err := s.Q.GetRecoveryEnvelope(r.Context(), db.GetRecoveryEnvelopeParams{VaultID: vaultID, KeyVersion: vault.KeyVersion})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"key_version": row.KeyVersion, "nonce": encodeB64(row.Nonce), "ciphertext": encodeB64(row.Ciphertext),
	})
}
