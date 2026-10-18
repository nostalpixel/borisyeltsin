package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nostalpixel/borisyeltsin/internal/db"
)

// vaultFixture is an organization with an owner who holds the vault key, an
// active recovery epoch (custodians: the owner and a second user), and a
// recovery envelope for key version 1.
type vaultFixture struct {
	srv       *Server
	q         *db.Queries
	h         http.Handler
	org       db.Organization
	owner     actor
	custodian actor
	recovery  recoveryKey
	vaultID   string
}

func newVaultFixture(t *testing.T) vaultFixture {
	t.Helper()
	srv, q := newServer(t)
	h := srv.Handler()
	org, err := q.CreateOrganization(context.Background(), "Vault "+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	owner := srv.addUser(t, q, org.ID, "admin", "active")
	approveKey(t, q, owner.user.ID)
	rec := call(h, http.MethodPost, "/api/v1/vaults", map[string]string{"name": "Team"}, &owner)
	if rec.Code != http.StatusCreated {
		t.Fatalf("vault %d %s", rec.Code, rec.Body.String())
	}
	var vault map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &vault)
	custodian := srv.addUser(t, q, org.ID, "member", "active")
	approveKey(t, q, custodian.user.ID)
	f := vaultFixture{srv: srv, q: q, h: h, org: org, owner: owner, custodian: custodian, vaultID: vault["id"].(string)}
	f.envelope(t, &owner, owner.user.ID, 1, http.StatusOK)
	f.recovery = seedRecovery(t, q, org.ID, owner.user.ID, owner.user.ID, custodian.user.ID)
	if rec := call(h, http.MethodPost, f.path("/recovery-envelope"), map[string]any{
		"epoch": f.recovery.epoch, "ciphertext": b64(160), "expected_key_version": 1,
	}, &owner); rec.Code != http.StatusOK {
		t.Fatalf("recovery envelope %d %s", rec.Code, rec.Body.String())
	}
	return f
}

func (f vaultFixture) path(suffix string) string { return "/api/v1/vaults/" + f.vaultID + suffix }

// approveKey stores an approved identity directly, as if a second admin had approved it.
func approveKey(t *testing.T, q *db.Queries, userID uuid.UUID) db.CryptoIdentity {
	t.Helper()
	pub := make([]byte, 32)
	copy(pub, userID[:])
	if _, err := q.InsertCryptoIdentity(context.Background(), db.InsertCryptoIdentityParams{
		UserID: userID, PublicKey: pub, Fingerprint: fingerprint(pub), KdfAlgorithm: "argon2id",
		KdfOpslimit: 3, KdfMemlimit: 67108864, KdfSalt: make([]byte, 16), PrivateKeyNonce: make([]byte, 24),
		PrivateKeyCiphertext: make([]byte, 48), RecoveryNonce: make([]byte, 24), RecoveryCiphertext: make([]byte, 48),
	}); err != nil {
		t.Fatal(err)
	}
	ident, err := q.ApproveCryptoIdentity(context.Background(), db.ApproveCryptoIdentityParams{UserID: userID})
	if err != nil {
		t.Fatal(err)
	}
	return ident
}

func (f vaultFixture) envelope(t *testing.T, by *actor, to uuid.UUID, keyVersion int, want int) {
	t.Helper()
	ident, err := f.q.GetCryptoIdentity(context.Background(), to)
	if err != nil {
		t.Fatal(err)
	}
	rec := call(f.h, http.MethodPost, f.path("/envelopes"), map[string]any{
		"user_id": to.String(), "fingerprint": ident.Fingerprint, "ciphertext": b64(80),
		"expected_key_version": keyVersion,
	}, by)
	if rec.Code != want {
		t.Fatalf("envelope want %d got %d %s", want, rec.Code, rec.Body.String())
	}
}

func (f vaultFixture) member(t *testing.T, role string) actor {
	t.Helper()
	a := f.srv.addUser(t, f.q, f.org.ID, "member", "active")
	approveKey(t, f.q, a.user.ID)
	if rec := call(f.h, http.MethodPost, f.path("/members"), map[string]string{
		"user_id": a.user.ID.String(), "role": role,
	}, &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("add member %d %s", rec.Code, rec.Body.String())
	}
	return a
}

func (f vaultFixture) createItem(t *testing.T, by *actor, keyVersion int) (string, int) {
	t.Helper()
	id := uuid.NewString()
	rec := call(f.h, http.MethodPost, f.path("/items"), map[string]any{
		"id": id, "nonce": b64(24), "ciphertext": b64(40), "expected_key_version": keyVersion,
	}, by)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create item %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return id, int(out["version"].(float64))
}

func (f vaultFixture) rotation(by *actor, expected int, items []map[string]any, envelopeFor []uuid.UUID) (int, string) {
	envs := []map[string]any{}
	for _, id := range envelopeFor {
		ident, _ := f.q.GetCryptoIdentity(context.Background(), id)
		envs = append(envs, map[string]any{"user_id": id.String(), "fingerprint": ident.Fingerprint, "ciphertext": b64(80)})
	}
	target, _ := sealTarget(context.Background(), f.q, f.org.ID)
	recovery := map[string]any{}
	if target != nil {
		recovery = map[string]any{"epoch": target.Epoch, "ciphertext": b64(160)}
	}
	rec := call(f.h, http.MethodPost, f.path("/rotation"), map[string]any{
		"expected_key_version": expected, "items": items, "envelopes": envs, "recovery": recovery,
	}, by)
	return rec.Code, rec.Body.String()
}

func errorCode(body string) string {
	var out map[string]string
	_ = json.Unmarshal([]byte(body), &out)
	return out["error"]
}

func TestAdminGetsNoVaultAccess(t *testing.T) {
	f := newVaultFixture(t)
	admin := f.srv.addUser(t, f.q, f.org.ID, "admin", "active")
	approveKey(t, f.q, admin.user.ID)
	rec := call(f.h, http.MethodPost, f.path("/members"), map[string]string{
		"user_id": admin.user.ID.String(), "role": "owner",
	}, &admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("admin self-add %d %s", rec.Code, rec.Body.String())
	}
	if _, err := f.q.GetVaultMember(context.Background(), db.GetVaultMemberParams{VaultID: uuid.MustParse(f.vaultID), UserID: admin.user.ID}); err == nil {
		t.Fatal("admin became a member")
	}
}

func TestOwnerWithoutKeyCannotManageOrRotate(t *testing.T) {
	f := newVaultFixture(t)
	keyless := f.member(t, "owner")
	other := f.srv.addUser(t, f.q, f.org.ID, "member", "active")
	approveKey(t, f.q, other.user.ID)
	rec := call(f.h, http.MethodPost, f.path("/members"), map[string]string{
		"user_id": other.user.ID.String(), "role": "member",
	}, &keyless)
	if rec.Code != http.StatusForbidden || errorCode(rec.Body.String()) != "not_key_holder" {
		t.Fatalf("keyless add %d %s", rec.Code, rec.Body.String())
	}
	code, body := f.rotation(&keyless, 1, []map[string]any{}, []uuid.UUID{f.owner.user.ID, keyless.user.ID})
	if code != http.StatusForbidden || errorCode(body) != "not_key_holder" {
		t.Fatalf("keyless rotation %d %s", code, body)
	}
}

func TestRotationRequiresTheCurrentItemSet(t *testing.T) {
	f := newVaultFixture(t)
	id, version := f.createItem(t, &f.owner, 1)
	owners := []uuid.UUID{f.owner.user.ID}
	if code, body := f.rotation(&f.owner, 1, []map[string]any{}, owners); code != http.StatusConflict || errorCode(body) != "items_changed" {
		t.Fatalf("empty item set %d %s", code, body)
	}
	stale := []map[string]any{{"id": id, "version": version + 1, "nonce": b64(24), "ciphertext": b64(40)}}
	if code, body := f.rotation(&f.owner, 1, stale, owners); code != http.StatusConflict || errorCode(body) != "item_conflict" {
		t.Fatalf("stale version %d %s", code, body)
	}
	items, err := f.q.ListVaultItems(context.Background(), uuid.MustParse(f.vaultID))
	if err != nil || len(items) != 1 {
		t.Fatalf("items after refused rotations %d %v", len(items), err)
	}
	good := []map[string]any{{"id": id, "version": version, "nonce": b64(24), "ciphertext": b64(40)}}
	if code, body := f.rotation(&f.owner, 1, good, owners); code != http.StatusOK {
		t.Fatalf("rotation %d %s", code, body)
	}
	if code, body := f.rotation(&f.owner, 1, good, owners); code != http.StatusConflict || errorCode(body) != "version_conflict" {
		t.Fatalf("replayed rotation %d %s", code, body)
	}
}

func TestWritesUnderAnOldKeyAreRefused(t *testing.T) {
	f := newVaultFixture(t)
	if code, body := f.rotation(&f.owner, 1, []map[string]any{}, []uuid.UUID{f.owner.user.ID}); code != http.StatusOK {
		t.Fatalf("rotation %d %s", code, body)
	}
	rec := call(f.h, http.MethodPost, f.path("/items"), map[string]any{
		"id": uuid.NewString(), "nonce": b64(24), "ciphertext": b64(40), "expected_key_version": 1,
	}, &f.owner)
	if rec.Code != http.StatusConflict || errorCode(rec.Body.String()) != "stale_key" {
		t.Fatalf("stale item %d %s", rec.Code, rec.Body.String())
	}
	f.envelope(t, &f.owner, f.owner.user.ID, 1, http.StatusConflict)
	rec = call(f.h, http.MethodPost, f.path("/recovery-envelope"), map[string]any{
		"epoch": f.recovery.epoch, "ciphertext": b64(160), "expected_key_version": 1,
	}, &f.owner)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale recovery envelope %d %s", rec.Code, rec.Body.String())
	}
	f.createItem(t, &f.owner, 2)
}

func TestItemEditsCarryAVersion(t *testing.T) {
	f := newVaultFixture(t)
	id, version := f.createItem(t, &f.owner, 1)
	update := func(v int) (int, string) {
		rec := call(f.h, http.MethodPut, f.path("/items/"+id), map[string]any{
			"nonce": b64(24), "ciphertext": b64(40), "expected_key_version": 1, "version": v,
		}, &f.owner)
		return rec.Code, rec.Body.String()
	}
	if code, body := update(version); code != http.StatusOK {
		t.Fatalf("first edit %d %s", code, body)
	}
	if code, body := update(version); code != http.StatusConflict || errorCode(body) != "item_conflict" {
		t.Fatalf("second edit from the same read %d %s", code, body)
	}
	if code, body := update(version + 1); code != http.StatusOK {
		t.Fatalf("edit from fresh read %d %s", code, body)
	}
}

func TestVaultKeepsAnOwner(t *testing.T) {
	f := newVaultFixture(t)
	rec := call(f.h, http.MethodDelete, f.path("/members/"+f.owner.user.ID.String()), nil, &f.owner)
	if rec.Code != http.StatusConflict || errorCode(rec.Body.String()) != "last_vault_owner" {
		t.Fatalf("remove sole owner %d %s", rec.Code, rec.Body.String())
	}
	rec = call(f.h, http.MethodPost, f.path("/members"), map[string]string{
		"user_id": f.owner.user.ID.String(), "role": "member",
	}, &f.owner)
	if rec.Code != http.StatusConflict || errorCode(rec.Body.String()) != "last_vault_owner" {
		t.Fatalf("demote sole owner %d %s", rec.Code, rec.Body.String())
	}
	soleOwner := f.member(t, "owner")
	if rec := call(f.h, http.MethodDelete, f.path("/members/"+f.owner.user.ID.String()), nil, &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("remove one of two owners %d %s", rec.Code, rec.Body.String())
	}
	admin := f.srv.addUser(t, f.q, f.org.ID, "admin", "active")
	rec = call(f.h, http.MethodPost, "/api/v1/users/"+soleOwner.user.ID.String()+"/revoke", map[string]any{}, &admin)
	if rec.Code != http.StatusConflict || errorCode(rec.Body.String()) != "last_vault_owner" {
		t.Fatalf("revoke sole owner %d %s", rec.Code, rec.Body.String())
	}
	user, err := f.q.GetUser(context.Background(), db.GetUserParams{ID: soleOwner.user.ID, OrganizationID: f.org.ID})
	if err != nil || user.Status != "active" {
		t.Fatalf("refused revoke changed status: %s %v", user.Status, err)
	}
}

func TestMissingEnvelopeMeansNoAccess(t *testing.T) {
	f := newVaultFixture(t)
	member := f.member(t, "member")
	rec := call(f.h, http.MethodGet, f.path("/envelope"), nil, &member)
	if rec.Code != http.StatusNotFound || errorCode(rec.Body.String()) != "no_access" {
		t.Fatalf("member without envelope %d %s", rec.Code, rec.Body.String())
	}
	// The vault is initialized, so nobody can write a "first" envelope for
	// themselves without holding the key.
	f.envelope(t, &member, member.user.ID, 1, http.StatusForbidden)
	f.envelope(t, &f.owner, member.user.ID, 1, http.StatusOK)
	if rec := call(f.h, http.MethodGet, f.path("/envelope"), nil, &member); rec.Code != http.StatusOK {
		t.Fatalf("shared envelope %d %s", rec.Code, rec.Body.String())
	}
}

func TestFirstEnvelopeIsTheOwnersOwn(t *testing.T) {
	srv, q := newServer(t)
	h := srv.Handler()
	org, err := q.CreateOrganization(context.Background(), "Init")
	if err != nil {
		t.Fatal(err)
	}
	owner := srv.addUser(t, q, org.ID, "admin", "active")
	approveKey(t, q, owner.user.ID)
	rec := call(h, http.MethodPost, "/api/v1/vaults", map[string]string{"name": "Team"}, &owner)
	var vault map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &vault)
	f := vaultFixture{srv: srv, q: q, h: h, org: org, owner: owner, vaultID: vault["id"].(string)}
	other := srv.addUser(t, q, org.ID, "member", "active")
	approveKey(t, q, other.user.ID)
	if err := q.UpsertVaultMember(context.Background(), db.UpsertVaultMemberParams{
		VaultID: uuid.MustParse(f.vaultID), UserID: other.user.ID, Role: "member",
	}); err != nil {
		t.Fatal(err)
	}
	f.envelope(t, &owner, other.user.ID, 1, http.StatusForbidden)
	f.envelope(t, &owner, owner.user.ID, 1, http.StatusOK)
	row, err := q.GetVault(context.Background(), db.GetVaultParams{ID: uuid.MustParse(f.vaultID), OrganizationID: org.ID})
	if err != nil || !row.Initialized {
		t.Fatalf("vault not initialized %v", err)
	}
}

// TestVaultWritesWaitForTheLock holds the vault row lock from a second
// connection, the way a slow rotation would, and checks both outcomes of the
// race: the waiting write sees the state committed before it, and a write
// that waits too long fails cleanly.
func TestVaultWritesWaitForTheLock(t *testing.T) {
	f := newVaultFixture(t)
	ctx := context.Background()
	vaultID := uuid.MustParse(f.vaultID)

	holder, err := f.srv.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, "SELECT 1 FROM vaults WHERE id = $1 FOR UPDATE", vaultID); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		rec := call(f.h, http.MethodPost, f.path("/items"), map[string]any{
			"id": uuid.NewString(), "nonce": b64(24), "ciphertext": b64(40), "expected_key_version": 1,
		}, &f.owner)
		done <- rec.Code
	}()
	select {
	case code := <-done:
		t.Fatalf("write finished while the vault was locked: %d", code)
	case <-time.After(300 * time.Millisecond):
	}
	// The holder rotates the key and commits; the waiting write must see it.
	if _, err := holder.Exec(ctx, "UPDATE vaults SET key_version = 2 WHERE id = $1", vaultID); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `INSERT INTO vault_key_envelopes (vault_id, user_id, key_version, recipient_fingerprint, ciphertext, created_by)
		SELECT vault_id, user_id, 2, recipient_fingerprint, ciphertext, created_by FROM vault_key_envelopes WHERE vault_id = $1`, vaultID); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != http.StatusConflict {
		t.Fatalf("write after rotation committed: want 409 stale_key, got %d", code)
	}
	items, err := f.q.ListVaultItems(ctx, vaultID)
	if err != nil || len(items) != 0 {
		t.Fatalf("refused write left %d items %v", len(items), err)
	}

	slow, err := f.srv.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Rollback(ctx)
	if _, err := slow.Exec(ctx, "SELECT 1 FROM vaults WHERE id = $1 FOR UPDATE", vaultID); err != nil {
		t.Fatal(err)
	}
	rec := call(f.h, http.MethodPost, f.path("/items"), map[string]any{
		"id": uuid.NewString(), "nonce": b64(24), "ciphertext": b64(40), "expected_key_version": 2,
	}, &f.owner)
	if rec.Code != http.StatusServiceUnavailable || errorCode(rec.Body.String()) != "vault_busy" {
		t.Fatalf("lock timeout %d %s", rec.Code, rec.Body.String())
	}
	var audits int
	if err := f.srv.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE organization_id = $1 AND action = 'vault_item_created'", f.org.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 0 {
		t.Fatalf("refused writes left %s audit rows", strconv.Itoa(audits))
	}
}

func TestServiceEditKeepsOmittedFields(t *testing.T) {
	srv, q := newServer(t)
	h := srv.Handler()
	org, err := q.CreateOrganization(context.Background(), "Edit")
	if err != nil {
		t.Fatal(err)
	}
	admin := srv.addUser(t, q, org.ID, "admin", "active")
	rec := call(h, http.MethodPost, "/api/v1/services", map[string]any{
		"name": "Zomro", "category": "infra", "url": "https://zomro.com", "notes": "billing via ops",
		"tags": []string{"vpn"}, "logo": "ZO", "logo_bg": "#112233", "logo_fg": "#445566",
	}, &admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	rec = call(h, http.MethodPatch, "/api/v1/services/"+created["id"].(string), map[string]any{
		"name": "Zomro VPN", "category": "infra", "url": "https://zomro.com", "description": "VPN", "unclear": false,
	}, &admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("edit %d %s", rec.Code, rec.Body.String())
	}
	row, err := q.GetService(context.Background(), db.GetServiceParams{ID: uuid.MustParse(created["id"].(string)), OrganizationID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	if row.Name != "Zomro VPN" || row.Notes != "billing via ops" || len(row.Tags) != 1 || row.Logo != "ZO" || row.LogoBg != "#112233" || row.LogoFg != "#445566" {
		t.Fatalf("omitted fields changed: %+v", row)
	}
}

func TestLinksMustPointInsideTheirParent(t *testing.T) {
	f := newVaultFixture(t)
	svc := call(f.h, http.MethodPost, "/api/v1/services", map[string]string{"name": "A", "category": "infra"}, &f.owner)
	var service map[string]any
	_ = json.Unmarshal(svc.Body.Bytes(), &service)
	acct := call(f.h, http.MethodPost, "/api/v1/services/"+service["id"].(string)+"/accounts", map[string]string{"label": "main"}, &f.owner)
	var account map[string]any
	_ = json.Unmarshal(acct.Body.Bytes(), &account)
	rec := call(f.h, http.MethodPost, "/api/v1/accounts/"+account["id"].(string)+"/vault-link", map[string]string{
		"vault_id": f.vaultID, "vault_item_id": uuid.NewString(),
	}, &f.owner)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("link to missing item %d %s", rec.Code, rec.Body.String())
	}
	other := call(f.h, http.MethodPost, "/api/v1/services", map[string]string{"name": "B", "category": "infra"}, &f.owner)
	var otherService map[string]any
	_ = json.Unmarshal(other.Body.Bytes(), &otherService)
	rec = call(f.h, http.MethodPost, "/api/v1/subscriptions", map[string]any{
		"service_id": otherService["id"], "account_id": account["id"], "billing_cycle": "monthly",
		"renewal_date": "2026-12-01", "cost": "10", "currency": "USD",
	}, &f.owner)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("subscription with foreign account %d %s", rec.Code, rec.Body.String())
	}
}
