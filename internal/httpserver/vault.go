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

func (s *Server) addVaultMember(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	vault, member, memberErr := s.memberVault(r.Context(), p, vaultID)
	if memberErr != nil && p.Role != "admin" {
		s.sendError(w, memberErr)
		return
	}
	if p.Role != "admin" && !authz.CanAdminVault(member.Role) {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	if memberErr != nil {
		vault, err = s.metaVault(r.Context(), p, vaultID)
		if err != nil {
			s.sendError(w, err)
			return
		}
	}
	var body struct {
		UserID uuid.UUID `json:"user_id"`
		Role   string    `json:"role"`
	}
	if !s.decode(w, r, &body) || !authz.ValidVaultRole(body.Role) {
		s.fail(w, http.StatusBadRequest, "bad_role")
		return
	}
	user, err := s.Q.GetUser(r.Context(), db.GetUserParams{ID: body.UserID, OrganizationID: p.OrgID})
	if err != nil || user.Status != "active" {
		s.fail(w, http.StatusBadRequest, "bad_member")
		return
	}
	if err := s.Q.UpsertVaultMember(r.Context(), db.UpsertVaultMemberParams{VaultID: vault.ID, UserID: body.UserID, Role: body.Role}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "vault_member_added", "vault", vault.ID.String(), map[string]string{"user_id": body.UserID.String(), "role": body.Role})
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
	_, member, memberErr := s.memberVault(r.Context(), p, vaultID)
	if memberErr != nil && p.Role != "admin" {
		s.sendError(w, memberErr)
		return
	}
	if p.Role != "admin" && !authz.CanAdminVault(member.Role) {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	defer tx.Rollback(r.Context())
	q := s.Q.WithTx(tx)
	if err := q.DeleteVaultMember(r.Context(), db.DeleteVaultMemberParams{VaultID: vaultID, UserID: userID}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := q.DeleteEnvelopeForMember(r.Context(), db.DeleteEnvelopeForMemberParams{VaultID: vaultID, UserID: userID}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := q.SetVaultRotationRequired(r.Context(), db.SetVaultRotationRequiredParams{ID: vaultID, RotationRequired: true}); err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := q.InsertCredentialFlag(r.Context(), db.InsertCredentialFlagParams{OrganizationID: p.OrgID, Reason: "member_removed"}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "vault_member_removed", "vault", vaultID.String(), map[string]string{"user_id": userID.String()})
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) approvedKey(ctx context.Context, org, userID uuid.UUID) (db.CryptoIdentity, error) {
	user, err := s.Q.GetUser(ctx, db.GetUserParams{ID: userID, OrganizationID: org})
	if err != nil || user.Status != "active" {
		return db.CryptoIdentity{}, errStatus(http.StatusBadRequest, "bad_recipient")
	}
	ident, err := s.Q.GetCryptoIdentity(ctx, userID)
	if err != nil || ident.Status != "approved" {
		return db.CryptoIdentity{}, errStatus(http.StatusBadRequest, "key_not_approved")
	}
	return ident, nil
}

func (s *Server) putEnvelope(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	vault, member, err := s.memberVault(r.Context(), p, vaultID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if !authz.CanAdminVault(member.Role) {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		UserID      uuid.UUID `json:"user_id"`
		Fingerprint string    `json:"fingerprint"`
		Ciphertext  string    `json:"ciphertext"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	ciphertext, err := decodeB64(body.Ciphertext, 0, 48, 8192)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_envelope")
		return
	}
	recipient, err := s.Q.GetVaultMember(r.Context(), db.GetVaultMemberParams{VaultID: vaultID, UserID: body.UserID})
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_recipient")
		return
	}
	_ = recipient
	ident, err := s.approvedKey(r.Context(), p.OrgID, body.UserID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if body.Fingerprint != ident.Fingerprint {
		s.fail(w, http.StatusBadRequest, "fingerprint_mismatch")
		return
	}
	members, err := s.Q.ListVaultMembers(r.Context(), vaultID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	existing := 0
	actorHas := false
	for _, item := range members {
		env, err := s.Q.GetEnvelope(r.Context(), db.GetEnvelopeParams{VaultID: vaultID, UserID: item.UserID, KeyVersion: vault.KeyVersion})
		if err == nil && len(env.Ciphertext) > 0 {
			existing++
			if item.UserID == p.UserID {
				actorHas = true
			}
		}
	}
	if existing > 0 && !actorHas {
		s.fail(w, http.StatusForbidden, "vault_locked")
		return
	}
	if existing == 0 && body.UserID != p.UserID {
		s.fail(w, http.StatusForbidden, "owner_envelope_first")
		return
	}
	if err := s.Q.UpsertEnvelope(r.Context(), db.UpsertEnvelopeParams{
		VaultID: vaultID, UserID: body.UserID, KeyVersion: vault.KeyVersion,
		RecipientFingerprint: ident.Fingerprint, Ciphertext: ciphertext, CreatedBy: p.UserID,
	}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "envelope_written", "vault", vaultID.String(), map[string]string{"user_id": body.UserID.String()})
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
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"vault_id": vaultID, "key_version": env.KeyVersion,
		"fingerprint": env.RecipientFingerprint, "ciphertext": encodeB64(env.Ciphertext),
	})
}

func (s *Server) requireItemAccess(ctx context.Context, p Principal, vaultID uuid.UUID, write bool) (db.Vault, db.VaultMember, error) {
	vault, member, err := s.memberVault(ctx, p, vaultID)
	if err != nil {
		return vault, member, err
	}
	if write && !authz.CanWriteVault(member.Role) {
		return vault, member, errStatus(http.StatusForbidden, "forbidden")
	}
	if _, err := s.Q.GetEnvelope(ctx, db.GetEnvelopeParams{VaultID: vaultID, UserID: p.UserID, KeyVersion: vault.KeyVersion}); err != nil {
		return vault, member, errStatus(http.StatusForbidden, "vault_locked")
	}
	return vault, member, nil
}

func (s *Server) listItems(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	vault, _, err := s.requireItemAccess(r.Context(), p, vaultID, false)
	if err != nil {
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
			"id": row.ID, "key_version": row.KeyVersion,
			"nonce": encodeB64(row.Nonce), "ciphertext": encodeB64(row.Ciphertext),
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) createItem(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	vault, _, err := s.requireItemAccess(r.Context(), p, vaultID, true)
	if err != nil {
		s.sendError(w, err)
		return
	}
	org, err := s.Q.GetOrganization(r.Context(), p.OrgID)
	if err != nil || !org.RecoveryReady {
		s.fail(w, http.StatusConflict, "recovery_not_ready")
		return
	}
	if _, err := s.Q.GetRecoveryEnvelope(r.Context(), db.GetRecoveryEnvelopeParams{VaultID: vaultID, KeyVersion: vault.KeyVersion}); err != nil {
		s.fail(w, http.StatusConflict, "recovery_envelope_missing")
		return
	}
	var body struct {
		ID         uuid.UUID `json:"id"`
		Nonce      string    `json:"nonce"`
		Ciphertext string    `json:"ciphertext"`
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
	row, err := s.Q.InsertVaultItem(r.Context(), db.InsertVaultItemParams{
		ID: body.ID, VaultID: vaultID, KeyVersion: vault.KeyVersion, Nonce: nonce, Ciphertext: ct, CreatedBy: p.UserID,
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "vault_item_created", "vault_item", row.ID.String(), nil)
	s.writeJSON(w, http.StatusCreated, map[string]any{"id": row.ID})
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
	vault, _, err := s.requireItemAccess(r.Context(), p, vaultID, true)
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	nonce, ct, err := itemCipher(body.Nonce, body.Ciphertext)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_item")
		return
	}
	if _, err := s.Q.UpdateVaultItem(r.Context(), db.UpdateVaultItemParams{
		ID: itemID, VaultID: vaultID, Nonce: nonce, Ciphertext: ct, KeyVersion: vault.KeyVersion, UpdatedBy: p.UserID,
	}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "vault_item_updated", "vault_item", itemID.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
	if _, _, err := s.requireItemAccess(r.Context(), p, vaultID, true); err != nil {
		s.sendError(w, err)
		return
	}
	if err := s.Q.SoftDeleteVaultItem(r.Context(), db.SoftDeleteVaultItemParams{ID: itemID, VaultID: vaultID, UpdatedBy: p.UserID}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "vault_item_deleted", "vault_item", itemID.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) rotateVault(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	_, member, err := s.memberVault(r.Context(), p, vaultID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if !authz.CanAdminVault(member.Role) {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		ExpectedVersion int32 `json:"expected_key_version"`
		Items           []struct {
			ID         uuid.UUID `json:"id"`
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
	if !s.decode(w, r, &body) {
		return
	}
	members, err := s.Q.ListVaultMembers(r.Context(), vaultID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if len(body.Envelopes) != len(members) {
		s.fail(w, http.StatusBadRequest, "envelope_set")
		return
	}
	wanted := map[uuid.UUID]db.ListVaultMembersRow{}
	for _, member := range members {
		wanted[member.UserID] = member
	}
	seen := map[uuid.UUID]bool{}
	for _, env := range body.Envelopes {
		if seen[env.UserID] {
			s.fail(w, http.StatusBadRequest, "envelope_set")
			return
		}
		seen[env.UserID] = true
		if _, ok := wanted[env.UserID]; !ok {
			s.fail(w, http.StatusBadRequest, "envelope_set")
			return
		}
		ident, err := s.approvedKey(r.Context(), p.OrgID, env.UserID)
		if err != nil || env.Fingerprint != ident.Fingerprint {
			s.fail(w, http.StatusBadRequest, "fingerprint_mismatch")
			return
		}
	}
	org, err := s.Q.GetOrganization(r.Context(), p.OrgID)
	if err != nil || !org.RecoveryReady || body.Recovery.Nonce == "" {
		s.fail(w, http.StatusConflict, "recovery_not_ready")
		return
	}
	keep := make([]uuid.UUID, 0, len(body.Items))
	itemSeen := map[uuid.UUID]bool{}
	type preparedItem struct {
		id    uuid.UUID
		nonce []byte
		ct    []byte
	}
	prepared := make([]preparedItem, 0, len(body.Items))
	for _, item := range body.Items {
		nonce, ct, err := itemCipher(item.Nonce, item.Ciphertext)
		if err != nil {
			s.fail(w, http.StatusBadRequest, "bad_item")
			return
		}
		id := item.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		if itemSeen[id] {
			s.fail(w, http.StatusBadRequest, "bad_item")
			return
		}
		itemSeen[id] = true
		keep = append(keep, id)
		prepared = append(prepared, preparedItem{id: id, nonce: nonce, ct: ct})
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	defer tx.Rollback(r.Context())
	q := s.Q.WithTx(tx)
	next := body.ExpectedVersion + 1
	for _, item := range prepared {
		// Update in place so service_accounts.vault_item_id survives. A delete
		// would SET NULL that foreign key before the same id could be inserted.
		row, err := q.UpsertVaultItem(r.Context(), db.UpsertVaultItemParams{
			ID: item.id, VaultID: vaultID, KeyVersion: next, Nonce: item.nonce, Ciphertext: item.ct, CreatedBy: p.UserID,
		})
		if isNoRows(err) || (err == nil && row.ID != item.id) {
			s.fail(w, http.StatusConflict, "item_conflict")
			return
		}
		if err != nil {
			s.sendError(w, err)
			return
		}
	}
	if len(keep) == 0 {
		if err := q.DeleteVaultItems(r.Context(), vaultID); err != nil {
			s.sendError(w, err)
			return
		}
	} else if err := q.DeleteVaultItemsExcept(r.Context(), db.DeleteVaultItemsExceptParams{VaultID: vaultID, KeepIds: keep}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := q.DeleteEnvelopesForVaultExceptVersion(r.Context(), db.DeleteEnvelopesForVaultExceptVersionParams{VaultID: vaultID, KeyVersion: next}); err != nil {
		s.sendError(w, err)
		return
	}
	for _, env := range body.Envelopes {
		ct, err := decodeB64(env.Ciphertext, 0, 48, 8192)
		if err != nil {
			s.fail(w, http.StatusBadRequest, "bad_envelope")
			return
		}
		if err := q.UpsertEnvelope(r.Context(), db.UpsertEnvelopeParams{
			VaultID: vaultID, UserID: env.UserID, KeyVersion: next, RecipientFingerprint: env.Fingerprint,
			Ciphertext: ct, CreatedBy: p.UserID,
		}); err != nil {
			s.sendError(w, err)
			return
		}
	}
	nonce, err := decodeB64(body.Recovery.Nonce, 24, 0, 0)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_envelope")
		return
	}
	ct, err := decodeB64(body.Recovery.Ciphertext, 0, 17, 8192)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_envelope")
		return
	}
	if err := q.UpsertRecoveryEnvelope(r.Context(), db.UpsertRecoveryEnvelopeParams{
		VaultID: vaultID, KeyVersion: next, Nonce: nonce, Ciphertext: ct,
	}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := q.DeleteRecoveryEnvelopesExceptVersion(r.Context(), db.DeleteRecoveryEnvelopesExceptVersionParams{VaultID: vaultID, KeyVersion: next}); err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := q.BumpVaultKeyVersion(r.Context(), db.BumpVaultKeyVersionParams{ID: vaultID, KeyVersion: body.ExpectedVersion}); err != nil {
		s.fail(w, http.StatusConflict, "version_conflict")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "vault_rotated", "vault", vaultID.String(), nil)
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
	vault, member, err := s.memberVault(r.Context(), p, vaultID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if !authz.CanAdminVault(member.Role) {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	nonce, err := decodeB64(body.Nonce, 24, 0, 0)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_envelope")
		return
	}
	ct, err := decodeB64(body.Ciphertext, 0, 17, 8192)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_envelope")
		return
	}
	if err := s.Q.UpsertRecoveryEnvelope(r.Context(), db.UpsertRecoveryEnvelopeParams{
		VaultID: vaultID, KeyVersion: vault.KeyVersion, Nonce: nonce, Ciphertext: ct,
	}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "recovery_envelope_written", "vault", vaultID.String(), nil)
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
