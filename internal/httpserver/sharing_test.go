package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestPassphraseChangeKeepsTheKey(t *testing.T) {
	f := newVaultFixture(t)
	before, err := f.q.GetCryptoIdentity(context.Background(), f.owner.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	body := func(fp string, ops int) map[string]any {
		return map[string]any{
			"fingerprint": fp, "kdf_opslimit": ops, "kdf_memlimit": 67108864,
			"kdf_salt": b64(16), "private_key_nonce": b64(24), "private_key_ciphertext": b64(64),
		}
	}
	if rec := call(f.h, http.MethodPut, "/api/v1/crypto/identity/passphrase", body("not-my-key", 3), &f.owner); rec.Code != http.StatusConflict {
		t.Fatalf("wrong fingerprint %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(f.h, http.MethodPut, "/api/v1/crypto/identity/passphrase", body(before.Fingerprint, 2), &f.owner); rec.Code != http.StatusBadRequest {
		t.Fatalf("weak kdf %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(f.h, http.MethodPut, "/api/v1/crypto/identity/passphrase", body(before.Fingerprint, 3), &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("change %d %s", rec.Code, rec.Body.String())
	}
	after, err := f.q.GetCryptoIdentity(context.Background(), f.owner.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.PublicKey, before.PublicKey) || after.Status != "approved" || bytes.Equal(after.PrivateKeyCiphertext, before.PrivateKeyCiphertext) {
		t.Fatal("passphrase change must rewrap the backup and keep the approved public key")
	}
	if !bytes.Equal(after.RecoveryCiphertext, before.RecoveryCiphertext) {
		t.Fatal("passphrase change touched the recovery-key backup")
	}
	if rec := call(f.h, http.MethodGet, f.path("/envelope"), nil, &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("envelope after change %d", rec.Code)
	}
}

func TestRejectedProposalLeavesTheApprovedKey(t *testing.T) {
	f := newVaultFixture(t)
	member := f.member(t, "member")
	before, _ := f.q.GetCryptoIdentity(context.Background(), member.user.ID)
	if rec := call(f.h, http.MethodPost, "/api/v1/crypto/identity", fakeIdentity(), &member); rec.Code != http.StatusOK {
		t.Fatalf("propose %d %s", rec.Code, rec.Body.String())
	}
	rec := call(f.h, http.MethodGet, "/api/v1/crypto/proposals", nil, &f.owner)
	var listed struct {
		Proposals []struct {
			UserID string `json:"user_id"`
		} `json:"proposals"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	if rec.Code != http.StatusOK || len(listed.Proposals) != 1 || listed.Proposals[0].UserID != member.user.ID.String() {
		t.Fatalf("proposals %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(f.h, http.MethodGet, "/api/v1/crypto/proposals", nil, &member); rec.Code != http.StatusForbidden {
		t.Fatalf("member listing proposals %d", rec.Code)
	}
	if rec := call(f.h, http.MethodPost, "/api/v1/crypto/users/"+member.user.ID.String()+"/reject", map[string]any{}, &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("reject %d %s", rec.Code, rec.Body.String())
	}
	after, _ := f.q.GetCryptoIdentity(context.Background(), member.user.ID)
	if after.Fingerprint != before.Fingerprint || after.Status != "approved" {
		t.Fatal("rejecting a proposal changed the approved key")
	}
	if _, err := f.q.GetCryptoProposal(context.Background(), member.user.ID); err == nil {
		t.Fatal("proposal still stored")
	}
}

func TestOneVaultPerOrganization(t *testing.T) {
	f := newVaultFixture(t)
	rec := call(f.h, http.MethodPost, "/api/v1/vaults", map[string]string{"name": "Second"}, &f.owner)
	if rec.Code != http.StatusConflict || errorCode(rec.Body.String()) != "vault_exists" {
		t.Fatalf("second vault %d %s", rec.Code, rec.Body.String())
	}
}

func TestVaultDetailShowsWhoHoldsTheKey(t *testing.T) {
	f := newVaultFixture(t)
	member := f.member(t, "member")
	rec := call(f.h, http.MethodGet, f.path(""), nil, &f.owner)
	var detail struct {
		Members []struct {
			UserID string `json:"user_id"`
			HasKey bool   `json:"has_key"`
		} `json:"members"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &detail)
	got := map[string]bool{}
	for _, m := range detail.Members {
		got[m.UserID] = m.HasKey
	}
	if !got[f.owner.user.ID.String()] || got[member.user.ID.String()] {
		t.Fatalf("has_key %v", got)
	}
	f.envelope(t, &f.owner, member.user.ID, 1, http.StatusOK)
	rec = call(f.h, http.MethodGet, f.path(""), nil, &f.owner)
	_ = json.Unmarshal(rec.Body.Bytes(), &detail)
	for _, m := range detail.Members {
		if !m.HasKey {
			t.Fatalf("after sharing %+v", detail.Members)
		}
	}
}

func TestRejectedKeyCanBeReplaced(t *testing.T) {
	f := newVaultFixture(t)
	newcomer := f.srv.addUser(t, f.q, f.org.ID, "member", "pending_enrollment")
	if rec := call(f.h, http.MethodPost, "/api/v1/crypto/identity", fakeIdentity(), &newcomer); rec.Code != http.StatusOK {
		t.Fatalf("enroll %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(f.h, http.MethodPost, "/api/v1/crypto/users/"+newcomer.user.ID.String()+"/reject", map[string]any{}, &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("reject %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(f.h, http.MethodPost, "/api/v1/crypto/identity", fakeIdentity(), &newcomer); rec.Code != http.StatusOK {
		t.Fatalf("enroll after rejection %d %s", rec.Code, rec.Body.String())
	}
	ident, err := f.q.GetCryptoIdentity(context.Background(), newcomer.user.ID)
	if err != nil || ident.Status != "pending" {
		t.Fatalf("after re-enroll: %s %v", ident.Status, err)
	}
}

// libsodium needs WebAssembly for Argon2id; the policy must allow compiling it
// and nothing broader.
func TestCSPAllowsWebAssemblyOnly(t *testing.T) {
	srv, _ := newServer(t)
	rec := call(srv.Handler(), http.MethodGet, "/healthz", nil, nil)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'wasm-unsafe-eval';") {
		t.Fatalf("script-src: %s", csp)
	}
	if strings.Contains(csp, "'unsafe-eval'") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("policy allows eval or inline script: %s", csp)
	}
}
