package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nostalpixel/borisyeltsin/internal/config"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/testpg"
	"github.com/nostalpixel/borisyeltsin/internal/token"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testpg.Stop()
	os.Exit(code)
}

func newServer(t *testing.T) (*Server, *db.Queries) {
	t.Helper()
	pool := testpg.Pool(t)
	srv := New(pool, config.Config{
		CookieSecure: false,
		SessionTTL:   12 * time.Hour,
		TimeZone:     "UTC",
		PublicURL:    "http://example.test",
		MFAAMR:       []string{"mfa", "otp", "totp", "webauthn"},
	})
	return srv, db.New(pool)
}

type actor struct {
	user   db.User
	cookie *http.Cookie
	csrf   string
}

func (s *Server) addUser(t *testing.T, q *db.Queries, org uuid.UUID, role, status string) actor {
	t.Helper()
	user, err := q.CreateUser(context.Background(), db.CreateUserParams{
		OrganizationID: org,
		Issuer:         "https://authentik.example/application/o/boris/",
		Subject:        uuid.NewString(),
		Email:          uuid.NewString() + "@example.com",
		DisplayName:    "Tester",
		Role:           role,
		Status:         status,
	})
	if err != nil {
		t.Fatal(err)
	}
	return newSession(t, q, user)
}

// newSession stores a session the way finishLogin does: the cookie holds the
// token, the database holds its SHA-256.
func newSession(t *testing.T, q *db.Queries, user db.User) actor {
	t.Helper()
	secret, err := newSecret()
	if err != nil {
		t.Fatal(err)
	}
	plain, hash, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateSession(context.Background(), db.CreateSessionParams{
		TokenHash: hash, UserID: user.ID, CsrfSecret: secret, Amr: []string{"pwd", "mfa"},
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return actor{user: user, csrf: secret, cookie: &http.Cookie{Name: "be_session", Value: plain}}
}

func call(handler http.Handler, method, path string, body any, a *actor) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("X-Requested-With", "fetch")
	if a != nil {
		req.AddCookie(a.cookie)
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestHealthAndInviteRules(t *testing.T) {
	srv, q := newServer(t)
	h := srv.Handler()
	if rec := call(h, http.MethodGet, "/healthz", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("health %d", rec.Code)
	}
	org, err := q.CreateOrganization(context.Background(), "Org")
	if err != nil {
		t.Fatal(err)
	}
	plain, hash, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := q.CreateInvitation(context.Background(), db.CreateInvitationParams{
		OrganizationID: org.ID, TokenHash: hash, IntendedIssuer: "https://idp.example",
		IntendedSubject: "subject-1", IntendedEmail: "a@example.com", Role: "admin",
		ExpiresAt: time.Now().Add(token.InviteTTL),
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := inv.ExpiresAt.Sub(time.Now()); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("ttl %s", d)
	}
	session, code := srv.finishLogin(context.Background(), identityClaims{
		Issuer: "https://idp.example", Subject: "other", Email: "a@example.com", AMR: []string{"mfa"},
	}, hash)
	if code != "access_denied" || session != "" {
		t.Fatalf("mismatch session=%q code=%s", session, code)
	}
	stored, err := q.GetInvitationByHash(context.Background(), hash)
	if err != nil || stored.AcceptedAt.Valid {
		t.Fatal("mismatch consumed the invitation", err)
	}
	session, code = srv.finishLogin(context.Background(), identityClaims{
		Issuer: "https://idp.example", Subject: "subject-1", Email: "a@example.com", Name: "Ada", AMR: []string{"mfa"},
	}, hash)
	if code != "" || session == "" {
		t.Fatal(code)
	}
	_, code = srv.finishLogin(context.Background(), identityClaims{
		Issuer: "https://idp.example", Subject: "intruder", AMR: []string{"mfa"},
	}, hash)
	if code != "access_denied" {
		t.Fatalf("replay %s", code)
	}
	_, code = srv.finishLogin(context.Background(), identityClaims{
		Issuer: "https://idp.example", Subject: "subject-1", AMR: []string{"pwd"},
	}, nil)
	if code != "access_denied" {
		t.Fatalf("mfa %s", code)
	}
	expiredHash := token.Hash("expired-token-value-with-enough-length")
	_, err = q.CreateInvitation(context.Background(), db.CreateInvitationParams{
		OrganizationID: org.ID, TokenHash: expiredHash, IntendedIssuer: "https://idp.example",
		IntendedSubject: "late", IntendedEmail: "late@example.com", Role: "member",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, code = srv.finishLogin(context.Background(), identityClaims{
		Issuer: "https://idp.example", Subject: "late", AMR: []string{"mfa"},
	}, expiredHash)
	if code != "access_denied" {
		t.Fatalf("expired %s", code)
	}
	if plain == "" {
		t.Fatal("token")
	}
}

func TestAuthorizationCSRFAndVaultBoundary(t *testing.T) {
	srv, q := newServer(t)
	h := srv.Handler()
	org, err := q.CreateOrganization(context.Background(), "Team")
	if err != nil {
		t.Fatal(err)
	}
	admin := srv.addUser(t, q, org.ID, "admin", "active")
	manager := srv.addUser(t, q, org.ID, "manager", "active")
	rec := call(h, http.MethodPost, "/api/v1/services", map[string]any{
		"name": "Zomro", "category": "infra", "url": "https://zomro.com", "description": "VPN",
	}, &admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	serviceID := created["id"].(string)

	bare := httptest.NewRequest(http.MethodPatch, "/api/v1/services/"+serviceID, bytes.NewBufferString(`{"name":"x","category":"infra"}`))
	bare.AddCookie(manager.cookie)
	bareRec := httptest.NewRecorder()
	h.ServeHTTP(bareRec, bare)
	if bareRec.Code != http.StatusForbidden {
		t.Fatalf("csrf %d", bareRec.Code)
	}
	denied := call(h, http.MethodPatch, "/api/v1/services/"+serviceID, map[string]any{
		"name": "Nope", "category": "infra",
	}, &manager)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("manager edit %d %s", denied.Code, denied.Body.String())
	}

	ident := fakeIdentity()
	enroll := call(h, http.MethodPost, "/api/v1/crypto/identity", ident, &admin)
	if enroll.Code != http.StatusForbidden && enroll.Code != http.StatusOK {
		// active user with no identity enrolls; status is active so proposal path needs an existing row.
	}
	// Admin is already active and has no identity, so enroll inserts the first key and moves status.
	if enroll.Code != http.StatusOK {
		t.Fatalf("enroll %d %s", enroll.Code, enroll.Body.String())
	}
	// Self approval is refused once a second user exists.
	approve := call(h, http.MethodPost, "/api/v1/crypto/users/"+admin.user.ID.String()+"/approve", map[string]any{}, &admin)
	if approve.Code != http.StatusForbidden {
		t.Fatalf("self approve %d %s", approve.Code, approve.Body.String())
	}

	soloOrg, err := q.CreateOrganization(context.Background(), "Solo")
	if err != nil {
		t.Fatal(err)
	}
	solo := srv.addUser(t, q, soloOrg.ID, "admin", "pending_enrollment")
	if rec := call(h, http.MethodPost, "/api/v1/crypto/identity", fakeIdentity(), &solo); rec.Code != http.StatusOK {
		t.Fatalf("solo enroll %d %s", rec.Code, rec.Body.String())
	}
	// Session still says pending_enrollment, but the row is pending_approval.
	solo.user.Status = "pending_approval"
	refreshed := srv.addUser(t, q, soloOrg.ID, "admin", "pending_approval")
	// The extra user blocks self-approval. Remove them by using a brand new org instead.
	_ = refreshed
	onlyOrg, err := q.CreateOrganization(context.Background(), "Only")
	if err != nil {
		t.Fatal(err)
	}
	only := srv.addUser(t, q, onlyOrg.ID, "admin", "pending_enrollment")
	body := fakeIdentity()
	if rec := call(h, http.MethodPost, "/api/v1/crypto/identity", body, &only); rec.Code != http.StatusOK {
		t.Fatalf("only enroll %d %s", rec.Code, rec.Body.String())
	}
	only = srv.addUser(t, q, onlyOrg.ID, "admin", "pending_approval")
	// addUser created a second admin. Approve as the enrolled user by rebuilding their session.
	enrolled, err := q.ListUsers(context.Background(), onlyOrg.ID)
	if err != nil {
		t.Fatal(err)
	}
	var subject db.User
	for _, user := range enrolled {
		if user.Status == "pending_approval" {
			subject = user
		}
	}
	owner := newSession(t, q, subject)
	// A second user exists, so self-approval must fail. Use an org with exactly one user.
	oneOrg, err := q.CreateOrganization(context.Background(), "One")
	if err != nil {
		t.Fatal(err)
	}
	one := srv.addUser(t, q, oneOrg.ID, "admin", "pending_enrollment")
	pub := fakeIdentity()
	if rec := call(h, http.MethodPost, "/api/v1/crypto/identity", pub, &one); rec.Code != http.StatusOK {
		t.Fatalf("one enroll %d %s", rec.Code, rec.Body.String())
	}
	one.user, err = q.GetUser(context.Background(), db.GetUserParams{ID: one.user.ID, OrganizationID: oneOrg.ID})
	if err != nil || one.user.Status != "pending_approval" {
		t.Fatalf("status %s %v", one.user.Status, err)
	}
	// Old session still has pending_enrollment in the cookie's user row, which is re-read.
	approved := call(h, http.MethodPost, "/api/v1/crypto/users/"+one.user.ID.String()+"/approve", map[string]any{}, &one)
	if approved.Code != http.StatusOK {
		t.Fatalf("approve %d %s", approved.Code, approved.Body.String())
	}
	one.user, _ = q.GetUser(context.Background(), db.GetUserParams{ID: one.user.ID, OrganizationID: oneOrg.ID})
	if one.user.Status != "active" {
		t.Fatal(one.user.Status)
	}
	vaultRec := call(h, http.MethodPost, "/api/v1/vaults", map[string]string{"name": "Infra"}, &one)
	if vaultRec.Code != http.StatusCreated {
		t.Fatalf("vault %d %s", vaultRec.Code, vaultRec.Body.String())
	}
	var vault map[string]any
	_ = json.Unmarshal(vaultRec.Body.Bytes(), &vault)
	vaultID := vault["id"].(string)
	identRow, err := q.GetCryptoIdentity(context.Background(), one.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	env := call(h, http.MethodPost, "/api/v1/vaults/"+vaultID+"/envelopes", map[string]any{
		"user_id": one.user.ID.String(), "fingerprint": identRow.Fingerprint, "ciphertext": pub["private_key_ciphertext"].(string),
		"expected_key_version": 1,
	}, &one)
	if env.Code != http.StatusOK {
		t.Fatalf("envelope %d %s", env.Code, env.Body.String())
	}
	other := srv.addUser(t, q, oneOrg.ID, "member", "active")
	stolen := call(h, http.MethodGet, "/api/v1/vaults/"+vaultID+"/envelope", nil, &other)
	if stolen.Code != http.StatusNotFound {
		t.Fatalf("idor %d %s", stolen.Code, stolen.Body.String())
	}
	items := call(h, http.MethodGet, "/api/v1/vaults/"+vaultID+"/items", nil, &other)
	if items.Code != http.StatusNotFound {
		t.Fatalf("items %d", items.Code)
	}
	_ = owner
}

func TestImportRejectsSecretsAndExportOmitsThem(t *testing.T) {
	srv, q := newServer(t)
	h := srv.Handler()
	org, err := q.CreateOrganization(context.Background(), "Import")
	if err != nil {
		t.Fatal(err)
	}
	admin := srv.addUser(t, q, org.ID, "admin", "active")
	bad := call(h, http.MethodPost, "/api/v1/imports/services", map[string]any{
		"version": 1,
		"services": []any{map[string]any{
			"name": "ChatGPT", "accounts": []any{map[string]any{"password": "hunter2"}},
		}},
	}, &admin)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("import secret %d %s", bad.Code, bad.Body.String())
	}
	good := call(h, http.MethodPost, "/api/v1/imports/services", map[string]any{
		"version": 1,
		"services": []any{map[string]any{
			"name": "Zomro", "url": "https://zomro.com/", "category": "infra", "description": "VPN",
			"logo": "ZO", "bg": "#eeeafc", "fg": "#7663c6",
			"accounts": []any{map[string]any{
				"label": "Аккаунт 1", "login": "ops@example.com", "password": "",
				"cost": "12.50", "currency": "USDT", "date": "2026-11-01", "card": "Visa 4242",
			}},
		}},
	}, &admin)
	if good.Code != http.StatusCreated {
		t.Fatalf("import %d %s", good.Code, good.Body.String())
	}
	exported := call(h, http.MethodGet, "/api/v1/exports/services.csv", nil, &admin)
	if exported.Code != http.StatusOK || bytes.Contains(exported.Body.Bytes(), []byte("hunter2")) {
		t.Fatalf("csv %d", exported.Code)
	}
	if !bytes.Contains(exported.Body.Bytes(), []byte("ops@example.com")) || !bytes.Contains(exported.Body.Bytes(), []byte("USDT")) {
		t.Fatalf("csv body %s", exported.Body.String())
	}
	card := call(h, http.MethodPost, "/api/v1/payment-methods", map[string]any{
		"nickname": "4111111111111111", "issuer": "Visa", "last4": "1111", "exp_month": 12, "exp_year": 2030,
	}, &admin)
	if card.Code != http.StatusBadRequest {
		t.Fatalf("pan %d %s", card.Code, card.Body.String())
	}
	method := call(h, http.MethodPost, "/api/v1/payment-methods", map[string]any{
		"nickname": "Corp Visa", "issuer": "Visa", "last4": "4242", "exp_month": 12, "exp_year": 2030,
	}, &admin)
	if method.Code != http.StatusCreated {
		t.Fatalf("method %d %s", method.Code, method.Body.String())
	}
}

func TestRevokeDropsSession(t *testing.T) {
	srv, q := newServer(t)
	h := srv.Handler()
	org, err := q.CreateOrganization(context.Background(), "Revoke")
	if err != nil {
		t.Fatal(err)
	}
	admin := srv.addUser(t, q, org.ID, "admin", "active")
	member := srv.addUser(t, q, org.ID, "member", "active")
	rec := call(h, http.MethodPost, "/api/v1/users/"+member.user.ID.String()+"/revoke", map[string]any{}, &admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke %d %s", rec.Code, rec.Body.String())
	}
	again := call(h, http.MethodGet, "/api/v1/session", nil, &member)
	if again.Code != http.StatusUnauthorized {
		t.Fatalf("session %d", again.Code)
	}
}

func TestRotationKeepsAccountLink(t *testing.T) {
	srv, q := newServer(t)
	h := srv.Handler()
	org, err := q.CreateOrganization(context.Background(), "Rotate")
	if err != nil {
		t.Fatal(err)
	}
	admin := srv.addUser(t, q, org.ID, "admin", "pending_enrollment")
	pub := fakeIdentity()
	if rec := call(h, http.MethodPost, "/api/v1/crypto/identity", pub, &admin); rec.Code != http.StatusOK {
		t.Fatalf("enroll %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(h, http.MethodPost, "/api/v1/crypto/users/"+admin.user.ID.String()+"/approve", map[string]any{}, &admin); rec.Code != http.StatusOK {
		t.Fatalf("approve %d %s", rec.Code, rec.Body.String())
	}
	vaultRec := call(h, http.MethodPost, "/api/v1/vaults", map[string]string{"name": "Ops"}, &admin)
	if vaultRec.Code != http.StatusCreated {
		t.Fatalf("vault %d %s", vaultRec.Code, vaultRec.Body.String())
	}
	var vault map[string]any
	_ = json.Unmarshal(vaultRec.Body.Bytes(), &vault)
	vaultID := vault["id"].(string)
	ident, err := q.GetCryptoIdentity(context.Background(), admin.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	env := call(h, http.MethodPost, "/api/v1/vaults/"+vaultID+"/envelopes", map[string]any{
		"user_id": admin.user.ID.String(), "fingerprint": ident.Fingerprint, "ciphertext": pub["private_key_ciphertext"].(string),
		"expected_key_version": 1,
	}, &admin)
	if env.Code != http.StatusOK {
		t.Fatalf("envelope %d %s", env.Code, env.Body.String())
	}
	if err := q.SetRecoveryReady(context.Background(), db.SetRecoveryReadyParams{ID: org.ID, RecoveryReady: true}); err != nil {
		t.Fatal(err)
	}
	recEnv := call(h, http.MethodPost, "/api/v1/vaults/"+vaultID+"/recovery-envelope", map[string]any{
		"nonce": b64(24), "ciphertext": b64(48), "expected_key_version": 1,
	}, &admin)
	if recEnv.Code != http.StatusOK {
		t.Fatalf("recovery envelope %d %s", recEnv.Code, recEnv.Body.String())
	}
	itemID := uuid.New()
	item := call(h, http.MethodPost, "/api/v1/vaults/"+vaultID+"/items", map[string]any{
		"id": itemID.String(), "nonce": b64(24), "ciphertext": b64(32), "expected_key_version": 1,
	}, &admin)
	if item.Code != http.StatusCreated {
		t.Fatalf("item %d %s", item.Code, item.Body.String())
	}
	svc := call(h, http.MethodPost, "/api/v1/services", map[string]string{"name": "Zomro", "category": "infra"}, &admin)
	if svc.Code != http.StatusCreated {
		t.Fatalf("service %d %s", svc.Code, svc.Body.String())
	}
	var service map[string]any
	_ = json.Unmarshal(svc.Body.Bytes(), &service)
	acct := call(h, http.MethodPost, "/api/v1/services/"+service["id"].(string)+"/accounts", map[string]string{"label": "main"}, &admin)
	if acct.Code != http.StatusCreated {
		t.Fatalf("account %d %s", acct.Code, acct.Body.String())
	}
	var account map[string]any
	_ = json.Unmarshal(acct.Body.Bytes(), &account)
	link := call(h, http.MethodPost, "/api/v1/accounts/"+account["id"].(string)+"/vault-link", map[string]string{
		"vault_id": vaultID, "vault_item_id": itemID.String(),
	}, &admin)
	if link.Code != http.StatusOK {
		t.Fatalf("link %d %s", link.Code, link.Body.String())
	}
	rotated := call(h, http.MethodPost, "/api/v1/vaults/"+vaultID+"/rotation", map[string]any{
		"expected_key_version": 1,
		"items": []map[string]any{{
			"id": itemID.String(), "version": 1, "nonce": b64(24), "ciphertext": b64(40),
		}},
		"envelopes": []map[string]string{{
			"user_id": admin.user.ID.String(), "fingerprint": ident.Fingerprint, "ciphertext": pub["recovery_ciphertext"].(string),
		}},
		"recovery": map[string]string{"nonce": b64(24), "ciphertext": b64(48)},
	}, &admin)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate %d %s", rotated.Code, rotated.Body.String())
	}
	row, err := q.GetAccount(context.Background(), db.GetAccountParams{
		ID: uuid.MustParse(account["id"].(string)), OrganizationID: org.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.VaultItemID == nil || *row.VaultItemID != itemID {
		t.Fatalf("link lost: %+v", row.VaultItemID)
	}
}

func fakeIdentity() map[string]any {
	return map[string]any{
		"public_key":             b64(32),
		"kdf_opslimit":           3,
		"kdf_memlimit":           67108864,
		"kdf_salt":               b64(16),
		"private_key_nonce":      b64(24),
		"private_key_ciphertext": b64(64),
		"recovery_nonce":         b64(24),
		"recovery_ciphertext":    b64(64),
	}
}

func b64(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return base64.StdEncoding.EncodeToString(raw)
}
