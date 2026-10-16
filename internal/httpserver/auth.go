package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/nostalpixel/boriseltsyn/internal/authz"
	"github.com/nostalpixel/boriseltsyn/internal/config"
	"github.com/nostalpixel/boriseltsyn/internal/db"
	"github.com/nostalpixel/boriseltsyn/internal/token"
	"golang.org/x/oauth2"
)

type oidcClient struct {
	provider *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// UseOIDC connects the server to the configured Authentik issuer.
func (s *Server) UseOIDC(ctx context.Context) error {
	if s.Cfg.OIDC.Issuer == "" {
		return nil
	}
	provider, err := oidc.NewProvider(ctx, s.Cfg.OIDC.Issuer)
	if err != nil {
		return err
	}
	s.OIDC = &oidcClient{
		provider: provider,
		oauth: oauth2.Config{
			ClientID:     s.Cfg.OIDC.ClientID,
			ClientSecret: s.Cfg.OIDC.ClientSecret,
			RedirectURL:  s.Cfg.OIDC.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: s.Cfg.OIDC.ClientID}),
	}
	return nil
}

type identityClaims struct {
	Issuer  string
	Subject string
	Email   string
	Name    string
	AMR     []string
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		s.fail(w, http.StatusServiceUnavailable, "oidc_not_configured")
		return
	}
	if !s.Limit.Allow("login:" + s.clientIP(r)) {
		s.fail(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	_ = s.Q.DeleteExpiredOIDCTransactions(r.Context())
	state, stateHash, err := token.New()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	nonce, _, err := token.New()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	verifier := oauth2.GenerateVerifier()
	var inviteHash []byte
	if cookie, err := r.Cookie("be_invite"); err == nil && len(cookie.Value) <= 128 {
		inviteHash = token.Hash(cookie.Value)
	}
	err = s.Q.InsertOIDCTransaction(r.Context(), db.InsertOIDCTransactionParams{
		StateHash:       stateHash,
		Nonce:           nonce,
		CodeVerifier:    verifier,
		InviteTokenHash: inviteHash,
		ExpiresAt:       s.now().Add(10 * time.Minute),
	})
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	s.setCookie(w, "be_invite", "", "/api/v1/auth", -1)
	target := s.OIDC.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	deny := func() {
		http.Redirect(w, r, s.Cfg.PublicURL+"/?error=access_denied", http.StatusSeeOther)
	}
	if s.OIDC == nil || r.URL.Query().Get("error") != "" {
		deny()
		return
	}
	if !s.Limit.Allow("callback:" + s.clientIP(r)) {
		deny()
		return
	}
	state := r.URL.Query().Get("state")
	tx, err := s.Q.ConsumeOIDCTransaction(r.Context(), token.Hash(state))
	if err != nil {
		deny()
		return
	}
	oauthToken, err := s.OIDC.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(tx.CodeVerifier))
	if err != nil {
		deny()
		return
	}
	rawID, _ := oauthToken.Extra("id_token").(string)
	idToken, err := s.OIDC.verifier.Verify(r.Context(), rawID)
	if err != nil || idToken.Nonce != tx.Nonce || idToken.Subject == "" {
		deny()
		return
	}
	var parsed struct {
		Email string   `json:"email"`
		Name  string   `json:"name"`
		AMR   []string `json:"amr"`
	}
	if err := idToken.Claims(&parsed); err != nil {
		deny()
		return
	}
	session, code := s.finishLogin(r.Context(), identityClaims{
		Issuer:  idToken.Issuer,
		Subject: idToken.Subject,
		Email:   parsed.Email,
		Name:    parsed.Name,
		AMR:     parsed.AMR,
	}, tx.InviteTokenHash)
	if code != "" {
		deny()
		return
	}
	s.setCookie(w, "be_session", session.ID.String(), "/", int(s.Cfg.SessionTTL.Seconds()))
	http.Redirect(w, r, s.Cfg.PublicURL+"/", http.StatusSeeOther)
}

func (s *Server) finishLogin(ctx context.Context, claims identityClaims, inviteHash []byte) (db.Session, string) {
	if claims.Issuer == "" || claims.Subject == "" || !authz.MFASatisfied(claims.AMR, s.Cfg.MFAAMR) {
		return db.Session{}, "access_denied"
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return db.Session{}, "server"
	}
	defer tx.Rollback(ctx)
	q := s.Q.WithTx(tx)
	user, err := q.GetUserByIdentity(ctx, db.GetUserByIdentityParams{Issuer: claims.Issuer, Subject: claims.Subject})
	if isNoRows(err) {
		user, err = s.acceptInvite(ctx, q, claims, inviteHash)
	}
	if err != nil {
		if code, ok := loginCode(err); ok {
			return db.Session{}, code
		}
		return db.Session{}, "server"
	}
	if user.Status == "revoked" {
		s.audit(ctx, user.OrganizationID, &user.ID, "auth_revoked", "user", user.ID.String(), nil)
		return db.Session{}, "access_denied"
	}
	secret, err := newSecret()
	if err != nil {
		return db.Session{}, "server"
	}
	sessionID := uuid.New()
	session, err := q.CreateSession(ctx, db.CreateSessionParams{
		ID:         sessionID,
		UserID:     user.ID,
		CsrfSecret: secret,
		Amr:        claims.AMR,
		ExpiresAt:  s.now().Add(s.Cfg.SessionTTL),
	})
	if err != nil {
		return db.Session{}, "server"
	}
	actor := user.ID
	s.audit(ctx, user.OrganizationID, &actor, "auth_success", "user", user.ID.String(), nil)
	if err := tx.Commit(ctx); err != nil {
		return db.Session{}, "server"
	}
	return session, ""
}

func loginCode(err error) (string, bool) {
	if httpErr, ok := err.(httpError); ok && httpErr.code == "access_denied" {
		return httpErr.code, true
	}
	return "", false
}

func (s *Server) acceptInvite(ctx context.Context, q *db.Queries, claims identityClaims, inviteHash []byte) (db.User, error) {
	if len(inviteHash) == 0 {
		return db.User{}, errStatus(http.StatusForbidden, "access_denied")
	}
	inv, err := q.GetInvitationByHash(ctx, inviteHash)
	if err != nil || inv.AcceptedAt.Valid || inv.RevokedAt.Valid || !inv.ExpiresAt.After(s.now()) {
		return db.User{}, errStatus(http.StatusForbidden, "access_denied")
	}
	if inv.IntendedIssuer != claims.Issuer || inv.IntendedSubject != claims.Subject {
		s.audit(ctx, inv.OrganizationID, nil, "invite_mismatch", "invitation", inv.ID.String(), nil)
		return db.User{}, errStatus(http.StatusForbidden, "access_denied")
	}
	if _, err := q.AcceptInvitation(ctx, inv.ID); err != nil {
		return db.User{}, errStatus(http.StatusForbidden, "access_denied")
	}
	email := claims.Email
	if email == "" {
		email = inv.IntendedEmail
	}
	name := claims.Name
	if name == "" {
		name = email
	}
	user, err := q.CreateUser(ctx, db.CreateUserParams{
		OrganizationID: inv.OrganizationID,
		Issuer:         claims.Issuer,
		Subject:        claims.Subject,
		Email:          email,
		DisplayName:    name,
		Role:           inv.Role,
		Status:         "pending_enrollment",
	})
	if err != nil {
		return db.User{}, err
	}
	s.audit(ctx, inv.OrganizationID, &user.ID, "invite_accepted", "invitation", inv.ID.String(), nil)
	return user, nil
}

func (s *Server) stashInvite(w http.ResponseWriter, r *http.Request) {
	if !s.Limit.Allow("invite:" + s.clientIP(r)) {
		s.fail(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	if len(body.Token) < 20 || len(body.Token) > 128 {
		s.fail(w, http.StatusBadRequest, "invitation_invalid")
		return
	}
	s.setCookie(w, "be_invite", body.Token, "/api/v1/auth", 900)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"csrf_token": p.CSRF,
		"user": map[string]any{
			"id": p.UserID, "email": p.Email, "display_name": p.Name,
			"role": p.Role, "status": p.Status, "organization_id": p.OrgID,
		},
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	_ = s.Q.RevokeSession(r.Context(), p.SessionID)
	s.audit(r.Context(), p.OrgID, &p.UserID, "auth_logout", "session", p.SessionID.String(), nil)
	s.setCookie(w, "be_session", "", "/", -1)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type identityBody struct {
	PublicKey            string `json:"public_key"`
	KDFOpslimit          int32  `json:"kdf_opslimit"`
	KDFMemlimit          int32  `json:"kdf_memlimit"`
	KDFSalt              string `json:"kdf_salt"`
	PrivateKeyNonce      string `json:"private_key_nonce"`
	PrivateKeyCiphertext string `json:"private_key_ciphertext"`
	RecoveryNonce        string `json:"recovery_nonce"`
	RecoveryCiphertext   string `json:"recovery_ciphertext"`
}

func decodeIdentity(body identityBody) (db.InsertCryptoIdentityParams, string, error) {
	pub, err := decodeB64(body.PublicKey, 32, 0, 0)
	if err != nil {
		return db.InsertCryptoIdentityParams{}, "", err
	}
	salt, err := decodeB64(body.KDFSalt, 16, 0, 0)
	if err != nil {
		return db.InsertCryptoIdentityParams{}, "", err
	}
	pn, err := decodeB64(body.PrivateKeyNonce, 24, 0, 0)
	if err != nil {
		return db.InsertCryptoIdentityParams{}, "", err
	}
	pc, err := decodeB64(body.PrivateKeyCiphertext, 0, 48, 4096)
	if err != nil {
		return db.InsertCryptoIdentityParams{}, "", err
	}
	rn, err := decodeB64(body.RecoveryNonce, 24, 0, 0)
	if err != nil {
		return db.InsertCryptoIdentityParams{}, "", err
	}
	rc, err := decodeB64(body.RecoveryCiphertext, 0, 48, 4096)
	if err != nil {
		return db.InsertCryptoIdentityParams{}, "", err
	}
	if body.KDFOpslimit < 3 || body.KDFMemlimit < 67108864 {
		return db.InsertCryptoIdentityParams{}, "", errStatus(http.StatusBadRequest, "weak_kdf")
	}
	return db.InsertCryptoIdentityParams{
		PublicKey: pub, Fingerprint: fingerprint(pub), KdfAlgorithm: "argon2id",
		KdfOpslimit: body.KDFOpslimit, KdfMemlimit: body.KDFMemlimit, KdfSalt: salt,
		PrivateKeyNonce: pn, PrivateKeyCiphertext: pc, RecoveryNonce: rn, RecoveryCiphertext: rc,
	}, fingerprint(pub), nil
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if !s.Limit.Allow("enroll:" + p.UserID.String()) {
		s.fail(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var body identityBody
	if !s.decode(w, r, &body) {
		return
	}
	params, fp, err := decodeIdentity(body)
	if err != nil {
		if httpErr, ok := err.(httpError); ok {
			s.fail(w, httpErr.status, httpErr.code)
			return
		}
		s.fail(w, http.StatusBadRequest, "invalid_identity")
		return
	}
	params.UserID = p.UserID
	existing, err := s.Q.GetCryptoIdentity(r.Context(), p.UserID)
	if isNoRows(err) {
		if _, err := s.Q.InsertCryptoIdentity(r.Context(), params); err != nil {
			s.sendError(w, err)
			return
		}
		if p.Status == "pending_enrollment" {
			if _, err := s.Q.UpdateUserStatus(r.Context(), db.UpdateUserStatusParams{
				ID: p.UserID, OrganizationID: p.OrgID, Status: "pending_approval",
			}); err != nil {
				s.sendError(w, err)
				return
			}
		}
		s.audit(r.Context(), p.OrgID, &p.UserID, "crypto_enrolled", "user", p.UserID.String(), map[string]string{"fingerprint": fp})
		s.writeJSON(w, http.StatusOK, map[string]string{"fingerprint": fp, "status": "pending"})
		return
	}
	if err != nil {
		s.sendError(w, err)
		return
	}
	if existing.Status == "pending" {
		if err := s.Q.DeletePendingIdentity(r.Context(), p.UserID); err != nil {
			s.sendError(w, err)
			return
		}
		if _, err := s.Q.InsertCryptoIdentity(r.Context(), params); err != nil {
			s.sendError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]string{"fingerprint": fp, "status": "pending"})
		return
	}
	if existing.Status == "approved" && p.Status == "active" {
		if _, err := s.Q.UpsertCryptoProposal(r.Context(), db.UpsertCryptoProposalParams{
			UserID: p.UserID, PublicKey: params.PublicKey, Fingerprint: params.Fingerprint,
			KdfAlgorithm: params.KdfAlgorithm, KdfOpslimit: params.KdfOpslimit, KdfMemlimit: params.KdfMemlimit,
			KdfSalt: params.KdfSalt, PrivateKeyNonce: params.PrivateKeyNonce, PrivateKeyCiphertext: params.PrivateKeyCiphertext,
			RecoveryNonce: params.RecoveryNonce, RecoveryCiphertext: params.RecoveryCiphertext,
		}); err != nil {
			s.sendError(w, err)
			return
		}
		s.audit(r.Context(), p.OrgID, &p.UserID, "crypto_proposed", "user", p.UserID.String(), map[string]string{"fingerprint": fp})
		s.writeJSON(w, http.StatusOK, map[string]string{"fingerprint": fp, "status": "proposed"})
		return
	}
	s.fail(w, http.StatusConflict, "identity_state")
}

func (s *Server) myIdentity(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	row, err := s.Q.GetCryptoIdentity(r.Context(), p.UserID)
	if isNoRows(err) {
		s.writeJSON(w, http.StatusOK, map[string]any{"status": "missing"})
		return
	}
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, identityView(row))
}

func identityView(row db.CryptoIdentity) map[string]any {
	return map[string]any{
		"fingerprint": row.Fingerprint, "status": row.Status, "key_version": row.KeyVersion,
		"public_key":             encodeB64(row.PublicKey),
		"kdf_algorithm":          row.KdfAlgorithm,
		"kdf_opslimit":           row.KdfOpslimit,
		"kdf_memlimit":           row.KdfMemlimit,
		"kdf_salt":               encodeB64(row.KdfSalt),
		"private_key_nonce":      encodeB64(row.PrivateKeyNonce),
		"private_key_ciphertext": encodeB64(row.PrivateKeyCiphertext),
		"recovery_nonce":         encodeB64(row.RecoveryNonce),
		"recovery_ciphertext":    encodeB64(row.RecoveryCiphertext),
	}
}

func (s *Server) approveKey(w http.ResponseWriter, r *http.Request) {
	s.reviewKey(w, r, true)
}

func (s *Server) rejectKey(w http.ResponseWriter, r *http.Request) {
	s.reviewKey(w, r, false)
}

func (s *Server) reviewKey(w http.ResponseWriter, r *http.Request, approve bool) {
	p, _ := principalFrom(r)
	subjectID, err := pathID(r, "userID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	count, err := s.Q.CountUsers(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if !authz.CanApproveKey(p.UserID, subjectID, p.Role, p.Status, int(count)) {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	user, err := s.Q.GetUser(r.Context(), db.GetUserParams{ID: subjectID, OrganizationID: p.OrgID})
	if err != nil {
		s.sendError(w, err)
		return
	}
	ident, err := s.Q.GetCryptoIdentity(r.Context(), subjectID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	action := "crypto_rejected"
	if !approve {
		if ident.Status != "pending" {
			s.fail(w, http.StatusConflict, "nothing_to_review")
			return
		}
		if _, err := s.Q.RejectCryptoIdentity(r.Context(), db.RejectCryptoIdentityParams{UserID: subjectID, ApprovedBy: &p.UserID}); err != nil {
			s.sendError(w, err)
			return
		}
		s.audit(r.Context(), p.OrgID, &p.UserID, action, "user", subjectID.String(), map[string]string{"fingerprint": ident.Fingerprint})
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
		return
	}
	if ident.Status == "pending" {
		if _, err := s.Q.ApproveCryptoIdentity(r.Context(), db.ApproveCryptoIdentityParams{UserID: subjectID, ApprovedBy: &p.UserID}); err != nil {
			s.sendError(w, err)
			return
		}
		if user.Status == "pending_approval" {
			if _, err := s.Q.UpdateUserStatus(r.Context(), db.UpdateUserStatusParams{ID: subjectID, OrganizationID: p.OrgID, Status: "active"}); err != nil {
				s.sendError(w, err)
				return
			}
		}
		s.audit(r.Context(), p.OrgID, &p.UserID, "crypto_approved", "user", subjectID.String(), map[string]string{"fingerprint": ident.Fingerprint})
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "fingerprint": ident.Fingerprint})
		return
	}
	proposal, err := s.Q.GetCryptoProposal(r.Context(), subjectID)
	if err != nil {
		s.fail(w, http.StatusConflict, "nothing_to_review")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	defer tx.Rollback(r.Context())
	q := s.Q.WithTx(tx)
	if _, err := q.ReplaceCryptoIdentity(r.Context(), db.ReplaceCryptoIdentityParams{
		UserID: subjectID, PublicKey: proposal.PublicKey, Fingerprint: proposal.Fingerprint,
		KdfAlgorithm: proposal.KdfAlgorithm, KdfOpslimit: proposal.KdfOpslimit, KdfMemlimit: proposal.KdfMemlimit,
		KdfSalt: proposal.KdfSalt, PrivateKeyNonce: proposal.PrivateKeyNonce,
		PrivateKeyCiphertext: proposal.PrivateKeyCiphertext, RecoveryNonce: proposal.RecoveryNonce,
		RecoveryCiphertext: proposal.RecoveryCiphertext, ApprovedBy: &p.UserID,
	}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := q.DeleteCryptoProposal(r.Context(), subjectID); err != nil {
		s.sendError(w, err)
		return
	}
	if err := q.DeleteStaleEnvelopesForUser(r.Context(), db.DeleteStaleEnvelopesForUserParams{
		UserID: subjectID, RecipientFingerprint: proposal.Fingerprint,
	}); err != nil {
		s.sendError(w, err)
		return
	}
	vaultIDs, err := q.ListVaultIDsForUser(r.Context(), subjectID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	for _, id := range vaultIDs {
		if err := q.SetVaultRotationRequired(r.Context(), db.SetVaultRotationRequiredParams{ID: id, RotationRequired: true}); err != nil {
			s.sendError(w, err)
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "crypto_replaced", "user", subjectID.String(), map[string]string{"fingerprint": proposal.Fingerprint})
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "fingerprint": proposal.Fingerprint})
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	rows, err := s.Q.ListPublicKeys(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"user_id": row.UserID, "display_name": row.DisplayName, "email": row.Email,
			"user_status": row.UserStatus, "key_status": row.KeyStatus,
			"fingerprint": row.Fingerprint, "public_key": encodeB64(row.PublicKey),
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	rows, err := s.Q.ListUsers(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "email": row.Email, "display_name": row.DisplayName,
			"role": row.Role, "status": row.Status,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) changeRole(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	userID, err := pathID(r, "userID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if !s.decode(w, r, &body) || !authz.ValidAppRole(body.Role) {
		s.fail(w, http.StatusBadRequest, "bad_role")
		return
	}
	user, err := s.Q.GetUser(r.Context(), db.GetUserParams{ID: userID, OrganizationID: p.OrgID})
	if err != nil {
		s.sendError(w, err)
		return
	}
	if user.Role == "admin" && body.Role != "admin" {
		if err := s.keepAdmin(r.Context(), p.OrgID, userID); err != nil {
			s.sendError(w, err)
			return
		}
	}
	updated, err := s.Q.UpdateUserRole(r.Context(), db.UpdateUserRoleParams{ID: userID, OrganizationID: p.OrgID, Role: body.Role})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "role_changed", "user", userID.String(), map[string]string{"role": body.Role})
	s.writeJSON(w, http.StatusOK, map[string]string{"role": updated.Role})
}

func (s *Server) keepAdmin(ctx context.Context, org, except uuid.UUID) error {
	rows, err := s.Q.ListUsers(ctx, org)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID != except && row.Role == "admin" && row.Status == "active" {
			return nil
		}
	}
	return errStatus(http.StatusConflict, "last_admin")
}

func (s *Server) revokeUser(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	userID, err := pathID(r, "userID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	if userID == p.UserID {
		s.fail(w, http.StatusConflict, "last_admin")
		return
	}
	user, err := s.Q.GetUser(r.Context(), db.GetUserParams{ID: userID, OrganizationID: p.OrgID})
	if err != nil {
		s.sendError(w, err)
		return
	}
	if user.Role == "admin" && user.Status == "active" {
		if err := s.keepAdmin(r.Context(), p.OrgID, userID); err != nil {
			s.sendError(w, err)
			return
		}
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	defer tx.Rollback(r.Context())
	q := s.Q.WithTx(tx)
	if _, err := q.UpdateUserStatus(r.Context(), db.UpdateUserStatusParams{ID: userID, OrganizationID: p.OrgID, Status: "revoked"}); err != nil {
		s.sendError(w, err)
		return
	}
	if err := q.RevokeSessionsForUser(r.Context(), userID); err != nil {
		s.sendError(w, err)
		return
	}
	memberships, err := q.ListMembershipsForUser(r.Context(), userID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	for _, member := range memberships {
		if err := q.DeleteVaultMember(r.Context(), db.DeleteVaultMemberParams{VaultID: member.VaultID, UserID: userID}); err != nil {
			s.sendError(w, err)
			return
		}
		if err := q.SetVaultRotationRequired(r.Context(), db.SetVaultRotationRequiredParams{ID: member.VaultID, RotationRequired: true}); err != nil {
			s.sendError(w, err)
			return
		}
		if _, err := q.InsertCredentialFlag(r.Context(), db.InsertCredentialFlagParams{
			OrganizationID: p.OrgID, Reason: "offboarded",
		}); err != nil {
			s.sendError(w, err)
			return
		}
	}
	if err := q.DeleteEnvelopesForUser(r.Context(), userID); err != nil {
		s.sendError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "user_revoked", "user", userID.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) listInvitations(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	rows, err := s.Q.ListInvitations(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "email": row.IntendedEmail, "issuer": row.IntendedIssuer,
			"subject": row.IntendedSubject, "role": row.Role, "expires_at": row.ExpiresAt,
			"accepted": row.AcceptedAt.Valid, "revoked": row.RevokedAt.Valid,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"invitations": out})
}

func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
		Email   string `json:"email"`
		Role    string `json:"role"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	body.Issuer = strings.TrimSpace(body.Issuer)
	body.Subject = strings.TrimSpace(body.Subject)
	body.Email = strings.TrimSpace(body.Email)
	if body.Role == "" {
		body.Role = "member"
	}
	if body.Issuer == "" || body.Subject == "" || body.Email == "" || !authz.ValidAppRole(body.Role) {
		s.fail(w, http.StatusBadRequest, "bad_invitation")
		return
	}
	httpIssuer := strings.HasPrefix(body.Issuer, "https://") || strings.HasPrefix(body.Issuer, "http://")
	if _, err := url.ParseRequestURI(body.Issuer); err != nil || !httpIssuer {
		s.fail(w, http.StatusBadRequest, "bad_invitation")
		return
	}
	plain, hash, err := token.New()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	row, err := s.Q.CreateInvitation(r.Context(), db.CreateInvitationParams{
		OrganizationID: p.OrgID, TokenHash: hash, IntendedIssuer: body.Issuer,
		IntendedSubject: body.Subject, IntendedEmail: body.Email, Role: body.Role,
		ExpiresAt: s.now().Add(token.InviteTTL), CreatedBy: &p.UserID,
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "invite_created", "invitation", row.ID.String(), map[string]string{"email": body.Email})
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id": row.ID, "expires_at": row.ExpiresAt, "token": plain,
	})
}

func (s *Server) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	id, err := pathID(r, "invitationID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := s.Q.RevokeInvitation(r.Context(), db.RevokeInvitationParams{ID: id, OrganizationID: p.OrgID}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "invite_revoked", "invitation", id.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Bootstrap creates the first organization and prints nothing itself.
// The caller must show the returned token once.
func Bootstrap(ctx context.Context, q *db.Queries, cfg config.Config) (string, bool, error) {
	if !cfg.Bootstrap.Enabled() {
		return "", false, nil
	}
	users, err := q.CountAllUsers(ctx)
	if err != nil || users > 0 {
		return "", false, err
	}
	orgs, err := q.CountOrganizations(ctx)
	if err != nil {
		return "", false, err
	}
	var org db.Organization
	if orgs == 0 {
		org, err = q.CreateOrganization(ctx, cfg.Bootstrap.OrgName)
	} else {
		org, err = q.FirstOrganization(ctx)
	}
	if err != nil {
		return "", false, err
	}
	plain, hash, err := token.New()
	if err != nil {
		return "", false, err
	}
	inv, err := q.CreateInvitation(ctx, db.CreateInvitationParams{
		OrganizationID: org.ID, TokenHash: hash, IntendedIssuer: cfg.Bootstrap.Issuer,
		IntendedSubject: cfg.Bootstrap.Subject, IntendedEmail: cfg.Bootstrap.Email,
		Role: "admin", ExpiresAt: time.Now().Add(token.InviteTTL),
	})
	if err != nil {
		return "", false, err
	}
	_ = q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		OrganizationID: org.ID, Action: "bootstrap_invite", TargetType: "invitation",
		TargetID: inv.ID.String(), Metadata: []byte(`{}`),
	})
	return plain, true, nil
}
