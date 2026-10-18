package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nostalpixel/borisyeltsin/internal/authz"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"golang.org/x/crypto/nacl/box"
)

// Organization recovery, format 2. docs/CRYPTO.md "Organization recovery" is
// the specification; the server never sees a share or the recovery private key.
//
//	epoch status   pending -> confirmed -> active -> degraded | spent -> retired
//	pending        boxed shares stored, waiting for both custodians to confirm
//	confirmed      both confirmed; becomes active with its first recovery envelope
//	active         recovery-ready; the only state that issues challenges
//	degraded       a custodian or the creator left; recovery refused
//	spent          used for a recovery; the private key is assumed copied
const (
	challengeTTL      = 5 * time.Minute
	grantTTL          = 15 * time.Minute
	challengesPerHour = 5
)

func optionalEpoch(epoch db.RecoveryEpoch, err error) (*db.RecoveryEpoch, error) {
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &epoch, nil
}

// recoveryReady reports the active epoch when the organization is
// recovery-ready: active status, and both custodians are active users whose
// approved key is still the one their share was sent to.
func recoveryReady(ctx context.Context, q *db.Queries, org uuid.UUID) (*db.RecoveryEpoch, error) {
	current, err := optionalEpoch(q.GetCurrentEpoch(ctx, org))
	if err != nil || current == nil || current.Status != "active" {
		return nil, err
	}
	custodians, err := q.ListEpochCustodians(ctx, db.ListEpochCustodiansParams{OrganizationID: org, Epoch: current.Epoch})
	if err != nil {
		return nil, err
	}
	if len(custodians) != 2 {
		return nil, nil
	}
	for _, c := range custodians {
		ident, err := approvedKeyQ(ctx, q, org, c.UserID)
		if err != nil || ident.Fingerprint != c.Fingerprint {
			return nil, nil
		}
	}
	return current, nil
}

// sealTarget is the epoch a new recovery envelope must be sealed to: a
// confirmed epoch waiting for activation, else a ready active epoch, else none.
func sealTarget(ctx context.Context, q *db.Queries, org uuid.UUID) (*db.RecoveryEpoch, error) {
	next, err := optionalEpoch(q.GetNextEpoch(ctx, org))
	if err != nil {
		return nil, err
	}
	if next != nil && next.Status == "confirmed" {
		return next, nil
	}
	return recoveryReady(ctx, q, org)
}

// recoveryEnvelope decodes a sealed recovery envelope.
func recoveryEnvelope(raw string) ([]byte, error) {
	ct, err := decodeB64(raw, 0, 48+32, 2048)
	if err != nil {
		return nil, errStatus(http.StatusBadRequest, "bad_envelope")
	}
	return ct, nil
}

// writeRecoveryEnvelope stores an envelope for the vault's current key under
// target, and activates target if it was only confirmed. Activation retires
// the previous epoch and deletes its envelopes in the same transaction.
func writeRecoveryEnvelope(ctx context.Context, q *db.Queries, p Principal, vault db.Vault, target db.RecoveryEpoch, ct []byte) error {
	if err := q.UpsertRecoveryEnvelope(ctx, db.UpsertRecoveryEnvelopeParams{
		VaultID: vault.ID, KeyVersion: vault.KeyVersion, Epoch: target.Epoch, Ciphertext: ct,
	}); err != nil {
		return err
	}
	if target.Status != "confirmed" {
		return nil
	}
	if err := q.RetireCurrentEpoch(ctx, p.OrgID); err != nil {
		return err
	}
	if err := q.SetEpochStatus(ctx, db.SetEpochStatusParams{OrganizationID: p.OrgID, Epoch: target.Epoch, Status: "active"}); err != nil {
		return err
	}
	if err := q.DeleteOrgRecoveryEnvelopesExceptEpoch(ctx, db.DeleteOrgRecoveryEnvelopesExceptEpochParams{OrganizationID: p.OrgID, Epoch: target.Epoch}); err != nil {
		return err
	}
	return auditTx(ctx, q, p.OrgID, &p.UserID, "recovery_epoch_activated", "organization", p.OrgID.String(), map[string]string{"epoch": itoa(target.Epoch)})
}

// degradeRecoveryFor applies "Readiness and custodian changes" for a user who
// was revoked (revoked=true) or whose key was replaced. Epochs being set up
// are abandoned; an active epoch becomes degraded and every vault of the
// organization needs rotation. Callers hold the organization's vault locks.
func degradeRecoveryFor(ctx context.Context, q *db.Queries, org, actor, userID uuid.UUID, revoked bool) error {
	rows, err := q.ListEpochsInvolvingUser(ctx, db.ListEpochsInvolvingUserParams{OrganizationID: org, UserID: userID})
	if err != nil {
		return err
	}
	degraded := false
	for _, row := range rows {
		if !row.IsCustodian && !(revoked && row.IsCreator) {
			continue
		}
		next := ""
		switch row.Status {
		case "pending", "confirmed":
			next = "retired"
		case "active":
			next = "degraded"
			degraded = true
		default:
			continue
		}
		if err := q.SetEpochStatus(ctx, db.SetEpochStatusParams{OrganizationID: org, Epoch: row.Epoch, Status: next}); err != nil {
			return err
		}
		if err := auditTx(ctx, q, org, &actor, "recovery_epoch_"+next, "organization", org.String(), map[string]string{
			"epoch": itoa(row.Epoch), "user_id": userID.String(),
		}); err != nil {
			return err
		}
	}
	if !degraded {
		return nil
	}
	vaults, err := q.ListVaults(ctx, org)
	if err != nil {
		return err
	}
	for _, vault := range vaults {
		if err := q.SetVaultRotationRequired(ctx, db.SetVaultRotationRequiredParams{ID: vault.ID, RotationRequired: true}); err != nil {
			return err
		}
	}
	return nil
}

// orgVaultIDs lists every vault of the organization, for paths that may
// degrade recovery and so must lock them all.
func orgVaultIDs(ctx context.Context, q *db.Queries, org uuid.UUID) ([]uuid.UUID, error) {
	vaults, err := q.ListVaults(ctx, org)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(vaults))
	for _, vault := range vaults {
		ids = append(ids, vault.ID)
	}
	return ids, nil
}

// liveGrant returns the caller's unused, unexpired recovery grant for the
// vault, provided its epoch is still the active one.
func liveGrant(ctx context.Context, q *db.Queries, p Principal, vaultID uuid.UUID) (db.RecoveryGrant, bool) {
	grant, err := q.GetLiveRecoveryGrant(ctx, db.GetLiveRecoveryGrantParams{CustodianID: p.UserID, VaultID: vaultID})
	if err != nil || grant.OrganizationID != p.OrgID {
		return db.RecoveryGrant{}, false
	}
	current, err := optionalEpoch(q.GetCurrentEpoch(ctx, p.OrgID))
	if err != nil || current == nil || current.Status != "active" || current.Epoch != grant.Epoch {
		return db.RecoveryGrant{}, false
	}
	return grant, true
}

type custodianView struct {
	ShareIndex  int16     `json:"share_index"`
	UserID      uuid.UUID `json:"user_id"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Fingerprint string    `json:"fingerprint"`
	Confirmed   bool      `json:"confirmed"`
	Active      bool      `json:"active"`
}

type epochView struct {
	Epoch              int32           `json:"epoch"`
	Status             string          `json:"status"`
	PublicKey          string          `json:"public_key"`
	Fingerprint        string          `json:"fingerprint"`
	CreatedBy          uuid.UUID       `json:"created_by"`
	CreatorPublicKey   string          `json:"creator_public_key"`
	CreatorFingerprint string          `json:"creator_fingerprint"`
	Custodians         []custodianView `json:"custodians"`
}

func viewEpoch(ctx context.Context, q *db.Queries, epoch *db.RecoveryEpoch) (*epochView, error) {
	if epoch == nil {
		return nil, nil
	}
	rows, err := q.ListEpochCustodians(ctx, db.ListEpochCustodiansParams{OrganizationID: epoch.OrganizationID, Epoch: epoch.Epoch})
	if err != nil {
		return nil, err
	}
	out := &epochView{
		Epoch: epoch.Epoch, Status: epoch.Status, PublicKey: encodeB64(epoch.PublicKey), Fingerprint: epoch.Fingerprint,
		CreatedBy: epoch.CreatedBy, CreatorPublicKey: encodeB64(epoch.CreatorPublicKey), CreatorFingerprint: epoch.CreatorFingerprint,
		Custodians: []custodianView{},
	}
	for _, row := range rows {
		out.Custodians = append(out.Custodians, custodianView{
			ShareIndex: row.ShareIndex, UserID: row.UserID, DisplayName: row.DisplayName, Email: row.Email,
			Fingerprint: row.Fingerprint, Confirmed: row.ConfirmedAt.Valid, Active: row.UserStatus == "active",
		})
	}
	return out, nil
}

func (s *Server) getRecovery(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	ctx := r.Context()
	current, err := optionalEpoch(s.Q.GetCurrentEpoch(ctx, p.OrgID))
	if err != nil {
		s.sendError(w, err)
		return
	}
	next, err := optionalEpoch(s.Q.GetNextEpoch(ctx, p.OrgID))
	if err != nil {
		s.sendError(w, err)
		return
	}
	ready, err := recoveryReady(ctx, s.Q, p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	last, err := s.Q.MaxEpoch(ctx, p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	// A custodian may not be a vault member, and needs the id to recover it.
	vaultRows, err := s.Q.ListVaults(ctx, p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	vaults := make([]map[string]any, 0, len(vaultRows))
	for _, row := range vaultRows {
		vaults = append(vaults, map[string]any{"id": row.ID, "name": row.Name})
	}
	currentView, err := viewEpoch(ctx, s.Q, current)
	if err != nil {
		s.sendError(w, err)
		return
	}
	nextView, err := viewEpoch(ctx, s.Q, next)
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"organization_id": p.OrgID, "recovery_ready": ready != nil, "max_epoch": last, "vaults": vaults,
		"current": currentView, "next": nextView,
	})
}

// createEpoch stores a new recovery key and the two boxed shares. Any epoch
// still being set up is abandoned; the current one stays until activation.
func (s *Server) createEpoch(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		// Epoch is the number the shares were boxed for; it must be the next one.
		Epoch      int32  `json:"epoch"`
		PublicKey  string `json:"public_key"`
		Custodians []struct {
			UserID      uuid.UUID `json:"user_id"`
			ShareIndex  int16     `json:"share_index"`
			Fingerprint string    `json:"fingerprint"`
			Nonce       string    `json:"nonce"`
			Ciphertext  string    `json:"share_ciphertext"`
		} `json:"custodians"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	publicKey, err := decodeB64(body.PublicKey, 32, 0, 0)
	if err != nil || len(body.Custodians) != 2 {
		s.fail(w, http.StatusBadRequest, "bad_recovery")
		return
	}
	a, b := body.Custodians[0], body.Custodians[1]
	if a.UserID == b.UserID || a.Fingerprint == b.Fingerprint || a.ShareIndex == b.ShareIndex {
		s.fail(w, http.StatusBadRequest, "custodians_not_distinct")
		return
	}
	type share struct {
		nonce, ct []byte
	}
	shares := make([]share, 2)
	for i, c := range body.Custodians {
		if c.ShareIndex != 1 && c.ShareIndex != 2 {
			s.fail(w, http.StatusBadRequest, "bad_recovery")
			return
		}
		nonce, err := decodeB64(c.Nonce, 24, 0, 0)
		if err != nil {
			s.fail(w, http.StatusBadRequest, "bad_recovery")
			return
		}
		ct, err := decodeB64(c.Ciphertext, 0, 16+32, 4096)
		if err != nil {
			s.fail(w, http.StatusBadRequest, "bad_recovery")
			return
		}
		shares[i] = share{nonce: nonce, ct: ct}
	}
	var created db.RecoveryEpoch
	err = s.inTx(r.Context(), func(q *db.Queries) error {
		ctx := r.Context()
		creator, err := approvedKeyQ(ctx, q, p.OrgID, p.UserID)
		if err != nil {
			return err
		}
		for _, c := range body.Custodians {
			ident, err := approvedKeyQ(ctx, q, p.OrgID, c.UserID)
			if err != nil || ident.Fingerprint != c.Fingerprint {
				return errStatus(http.StatusBadRequest, "fingerprint_mismatch")
			}
		}
		last, err := q.MaxEpoch(ctx, p.OrgID)
		if err != nil {
			return err
		}
		if body.Epoch != last+1 {
			return errStatus(http.StatusConflict, "recovery_epoch_changed")
		}
		if err := q.RetireNextEpoch(ctx, p.OrgID); err != nil {
			return err
		}
		created, err = q.InsertEpoch(ctx, db.InsertEpochParams{
			OrganizationID: p.OrgID, Epoch: last + 1, PublicKey: publicKey, Fingerprint: fingerprint(publicKey),
			CreatedBy: p.UserID, CreatorPublicKey: creator.PublicKey, CreatorFingerprint: creator.Fingerprint,
		})
		if err != nil {
			return err
		}
		for i, c := range body.Custodians {
			if err := q.InsertCustodian(ctx, db.InsertCustodianParams{
				OrganizationID: p.OrgID, Epoch: created.Epoch, ShareIndex: c.ShareIndex, UserID: c.UserID,
				Fingerprint: c.Fingerprint, ShareNonce: shares[i].nonce, ShareCiphertext: shares[i].ct,
			}); err != nil {
				return err
			}
		}
		return auditTx(ctx, q, p.OrgID, &p.UserID, "recovery_epoch_created", "organization", p.OrgID.String(), map[string]string{
			"epoch": itoa(created.Epoch), "fingerprint": created.Fingerprint,
		})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"epoch": created.Epoch, "fingerprint": created.Fingerprint})
}

// getRecoveryShare returns the caller's boxed share for an epoch (default:
// the one being set up if the caller is in it, else the current one).
func (s *Server) getRecoveryShare(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	ctx := r.Context()
	var epoch *db.RecoveryEpoch
	if raw := r.URL.Query().Get("epoch"); raw != "" {
		n, err := atoi32(raw)
		if err != nil {
			s.fail(w, http.StatusBadRequest, "bad_epoch")
			return
		}
		row, err := s.Q.GetEpoch(ctx, db.GetEpochParams{OrganizationID: p.OrgID, Epoch: n})
		if err != nil {
			s.fail(w, http.StatusNotFound, "not_found")
			return
		}
		epoch = &row
	} else {
		for _, get := range []func(context.Context, uuid.UUID) (db.RecoveryEpoch, error){s.Q.GetNextEpoch, s.Q.GetCurrentEpoch} {
			row, err := get(ctx, p.OrgID)
			if err != nil {
				continue
			}
			if _, err := s.Q.GetEpochCustodian(ctx, db.GetEpochCustodianParams{OrganizationID: p.OrgID, Epoch: row.Epoch, UserID: p.UserID}); err == nil {
				epoch = &row
				break
			}
		}
	}
	if epoch == nil || epoch.Status == "retired" {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	row, err := s.Q.GetEpochCustodian(ctx, db.GetEpochCustodianParams{OrganizationID: p.OrgID, Epoch: epoch.Epoch, UserID: p.UserID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"epoch": epoch.Epoch, "status": epoch.Status, "share_index": row.ShareIndex, "fingerprint": row.Fingerprint,
		"nonce": encodeB64(row.ShareNonce), "share_ciphertext": encodeB64(row.ShareCiphertext), "confirmed": row.ConfirmedAt.Valid,
		"public_key": encodeB64(epoch.PublicKey), "recovery_fingerprint": epoch.Fingerprint, "created_by": epoch.CreatedBy,
		"creator_public_key": encodeB64(epoch.CreatorPublicKey), "creator_fingerprint": epoch.CreatorFingerprint,
	})
}

// confirmShare records that a custodian opened their share and found the
// epoch's public key inside. The second confirmation makes the epoch confirmed.
func (s *Server) confirmShare(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	var body struct {
		Epoch       int32  `json:"epoch"`
		Fingerprint string `json:"fingerprint"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	err := s.inTx(r.Context(), func(q *db.Queries) error {
		ctx := r.Context()
		epoch, err := q.LockEpoch(ctx, db.LockEpochParams{OrganizationID: p.OrgID, Epoch: body.Epoch})
		if err != nil {
			return errStatus(http.StatusNotFound, "not_found")
		}
		if epoch.Status != "pending" {
			return errStatus(http.StatusConflict, "epoch_not_pending")
		}
		custodian, err := q.GetEpochCustodian(ctx, db.GetEpochCustodianParams{OrganizationID: p.OrgID, Epoch: epoch.Epoch, UserID: p.UserID})
		if err != nil {
			return errStatus(http.StatusNotFound, "not_found")
		}
		if body.Fingerprint != epoch.Fingerprint {
			return errStatus(http.StatusBadRequest, "fingerprint_mismatch")
		}
		if ident, err := approvedKeyQ(ctx, q, p.OrgID, p.UserID); err != nil || ident.Fingerprint != custodian.Fingerprint {
			return errStatus(http.StatusConflict, "key_changed")
		}
		if _, err := q.ConfirmCustodian(ctx, db.ConfirmCustodianParams{OrganizationID: p.OrgID, Epoch: epoch.Epoch, UserID: p.UserID}); err != nil {
			return err
		}
		if err := auditTx(ctx, q, p.OrgID, &p.UserID, "recovery_share_confirmed", "organization", p.OrgID.String(), map[string]string{"epoch": itoa(epoch.Epoch)}); err != nil {
			return err
		}
		confirmed, err := q.CountConfirmedCustodians(ctx, db.CountConfirmedCustodiansParams{OrganizationID: p.OrgID, Epoch: epoch.Epoch})
		if err != nil || confirmed < 2 {
			return err
		}
		return q.SetEpochStatus(ctx, db.SetEpochStatusParams{OrganizationID: p.OrgID, Epoch: epoch.Epoch, Status: "confirmed"})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) putRecoveryEnvelope(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		Epoch              int32  `json:"epoch"`
		Ciphertext         string `json:"ciphertext"`
		ExpectedKeyVersion int32  `json:"expected_key_version"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	ct, err := recoveryEnvelope(body.Ciphertext)
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
		target, err := sealTarget(r.Context(), q, p.OrgID)
		if err != nil {
			return err
		}
		if target == nil {
			return errStatus(http.StatusConflict, "recovery_not_ready")
		}
		if target.Epoch != body.Epoch {
			return errStatus(http.StatusConflict, "recovery_epoch_changed")
		}
		if err := writeRecoveryEnvelope(r.Context(), q, p, vault, *target, ct); err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "recovery_envelope_written", "vault", vaultID.String(), map[string]string{"epoch": itoa(target.Epoch)})
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
	ctx := r.Context()
	vault, err := s.Q.GetVault(ctx, db.GetVaultParams{ID: vaultID, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	member, memberErr := s.Q.GetVaultMember(ctx, db.GetVaultMemberParams{VaultID: vaultID, UserID: p.UserID})
	_, granted := liveGrant(ctx, s.Q, p, vaultID)
	if !granted && (memberErr != nil || !authz.CanReadVault(member.Role)) {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	row, err := s.Q.GetRecoveryEnvelope(ctx, db.GetRecoveryEnvelopeParams{VaultID: vaultID, KeyVersion: vault.KeyVersion})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"key_version": row.KeyVersion, "epoch": row.Epoch, "ciphertext": encodeB64(row.Ciphertext),
	})
}

// challengePlaintext is the canonical challenge from docs/CRYPTO.md
// "Recovering", step 2. Field order is fixed by the struct.
type challengePlaintext struct {
	V           int       `json:"v"`
	ChallengeID uuid.UUID `json:"challenge_id"`
	OrgID       uuid.UUID `json:"org_id"`
	VaultID     uuid.UUID `json:"vault_id"`
	Epoch       int32     `json:"epoch"`
	CustodianID uuid.UUID `json:"custodian_id"`
	Nonce       string    `json:"nonce"`
}

func (s *Server) createChallenge(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	var body struct {
		VaultID uuid.UUID `json:"vault_id"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	var out map[string]any
	err := s.inTx(r.Context(), func(q *db.Queries) error {
		ctx := r.Context()
		current, err := recoveryReady(ctx, q, p.OrgID)
		if err != nil {
			return err
		}
		if current == nil {
			return errStatus(http.StatusConflict, "recovery_unavailable")
		}
		if _, err := q.GetEpochCustodian(ctx, db.GetEpochCustodianParams{OrganizationID: p.OrgID, Epoch: current.Epoch, UserID: p.UserID}); err != nil {
			return errStatus(http.StatusForbidden, "not_custodian")
		}
		if _, err := q.GetVault(ctx, db.GetVaultParams{ID: body.VaultID, OrganizationID: p.OrgID}); err != nil {
			return errStatus(http.StatusNotFound, "not_found")
		}
		recent, err := q.CountRecentChallenges(ctx, db.CountRecentChallengesParams{CustodianID: p.UserID, CreatedAt: s.now().Add(-time.Hour)})
		if err != nil {
			return err
		}
		if recent >= challengesPerHour {
			return errStatus(http.StatusTooManyRequests, "too_many_challenges")
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		plain := challengePlaintext{
			V: 1, ChallengeID: uuid.New(), OrgID: p.OrgID, VaultID: body.VaultID, Epoch: current.Epoch,
			CustodianID: p.UserID, Nonce: encodeB64(nonce),
		}
		raw, err := json.Marshal(plain)
		if err != nil {
			return err
		}
		var recipient [32]byte
		copy(recipient[:], current.PublicKey)
		sealed, err := box.SealAnonymous(nil, raw, &recipient, rand.Reader)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		if err := q.InsertChallenge(ctx, db.InsertChallengeParams{
			ID: plain.ChallengeID, OrganizationID: p.OrgID, VaultID: body.VaultID, Epoch: current.Epoch,
			CustodianID: p.UserID, Digest: digest[:], ExpiresAt: s.now().Add(challengeTTL),
		}); err != nil {
			return err
		}
		out = map[string]any{"challenge_id": plain.ChallengeID, "epoch": current.Epoch, "sealed": encodeB64(sealed)}
		return auditTx(ctx, q, p.OrgID, &p.UserID, "recovery_challenge_issued", "vault", body.VaultID.String(), map[string]string{"epoch": itoa(current.Epoch)})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, out)
}

// createGrant claims a challenge and, if the answer matches, issues a
// 15-minute grant for one recovery rotation. A wrong answer still uses the
// challenge up, and the failure is audited.
func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	var body struct {
		ChallengeID uuid.UUID `json:"challenge_id"`
		Response    string    `json:"response"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	response, err := decodeB64(body.Response, 0, 1, 1024)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_response")
		return
	}
	var grant db.RecoveryGrant
	failure := ""
	err = s.inTx(r.Context(), func(q *db.Queries) error {
		ctx := r.Context()
		challenge, err := q.ClaimChallenge(ctx, db.ClaimChallengeParams{ID: body.ChallengeID, CustodianID: p.UserID})
		if isNoRows(err) {
			failure = "challenge_invalid"
			return auditTx(ctx, q, p.OrgID, &p.UserID, "recovery_challenge_failed", "organization", p.OrgID.String(), map[string]string{"reason": failure})
		}
		if err != nil {
			return err
		}
		digest := sha256.Sum256(response)
		current, err := recoveryReady(ctx, q, p.OrgID)
		if err != nil {
			return err
		}
		switch {
		case subtle.ConstantTimeCompare(digest[:], challenge.Digest) != 1:
			failure = "challenge_failed"
		case current == nil || current.Epoch != challenge.Epoch:
			failure = "recovery_unavailable"
		}
		if failure != "" {
			return auditTx(ctx, q, p.OrgID, &p.UserID, "recovery_challenge_failed", "vault", challenge.VaultID.String(), map[string]string{"reason": failure})
		}
		grant, err = q.InsertRecoveryGrant(ctx, db.InsertRecoveryGrantParams{
			OrganizationID: p.OrgID, VaultID: challenge.VaultID, Epoch: challenge.Epoch, CustodianID: p.UserID,
			ExpiresAt: s.now().Add(grantTTL),
		})
		if err != nil {
			return err
		}
		return auditTx(ctx, q, p.OrgID, &p.UserID, "recovery_grant_issued", "vault", challenge.VaultID.String(), map[string]string{"epoch": itoa(challenge.Epoch)})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	if failure != "" {
		s.fail(w, http.StatusForbidden, failure)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"grant_id": grant.ID, "vault_id": grant.VaultID, "expires_at": grant.ExpiresAt})
}
