package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func rawCall(h http.Handler, method, path, contentType string, body []byte, a *actor) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("X-Requested-With", "fetch")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if a != nil {
		req.AddCookie(a.cookie)
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func randomBlob(t *testing.T, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		t.Fatal(err)
	}
	return out
}

// fileAccount makes a service owned by the vault owner with one account.
func (f vaultFixture) fileAccount(t *testing.T) (serviceID, accountID string) {
	t.Helper()
	svc := call(f.h, http.MethodPost, "/api/v1/services", map[string]string{"name": "Linode " + uuid.NewString()[:6], "category": "infra"}, &f.owner)
	if svc.Code != http.StatusCreated {
		t.Fatalf("service %d %s", svc.Code, svc.Body)
	}
	var service map[string]any
	_ = json.Unmarshal(svc.Body.Bytes(), &service)
	acct := call(f.h, http.MethodPost, "/api/v1/services/"+service["id"].(string)+"/accounts", map[string]string{"label": "main"}, &f.owner)
	if acct.Code != http.StatusCreated {
		t.Fatalf("account %d %s", acct.Code, acct.Body)
	}
	var account map[string]any
	_ = json.Unmarshal(acct.Body.Bytes(), &account)
	return service["id"].(string), account["id"].(string)
}

func (f vaultFixture) upload(by *actor, accountID string, blob []byte) (string, *httptest.ResponseRecorder) {
	id := uuid.NewString()
	return id, rawCall(f.h, http.MethodPost, f.path("/files?id="+id+"&account="+accountID), "application/octet-stream", blob, by)
}

func TestAccountFilesRoundTripAndAccess(t *testing.T) {
	f := newVaultFixture(t)
	serviceID, accountID := f.fileAccount(t)
	blob := randomBlob(t, 4096)
	fileID, rec := f.upload(&f.owner, accountID, blob)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload %d %s", rec.Code, rec.Body)
	}
	got := call(f.h, http.MethodGet, f.path("/files/"+fileID), nil, &f.owner)
	if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), blob) {
		t.Fatalf("download %d, %d bytes", got.Code, got.Body.Len())
	}
	if got.Header().Get("Content-Type") != "application/octet-stream" || got.Header().Get("Content-Disposition") != "attachment" {
		t.Fatalf("download headers %v", got.Header())
	}
	if got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control %q", got.Header().Get("Cache-Control"))
	}
	var audited int
	if err := f.srv.Pool.QueryRow(context.Background(),
		"SELECT count(*) FROM audit_events WHERE action = 'vault_file_added' AND target_id = $1", fileID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("audit rows %d %v", audited, err)
	}

	// A vault member who cannot see the service gets nothing, even with the key.
	reader := f.member(t, "member")
	f.envelope(t, &f.owner, reader.user.ID, 1, http.StatusOK)
	if rec := call(f.h, http.MethodGet, f.path("/files/"+fileID), nil, &reader); rec.Code != http.StatusNotFound {
		t.Fatalf("hidden service download %d", rec.Code)
	}
	// With a grant the member can read, but a vault "member" cannot write.
	if rec := call(f.h, http.MethodPost, "/api/v1/services/"+serviceID+"/grants", map[string]string{"user_id": reader.user.ID.String()}, &f.owner); rec.Code/100 != 2 {
		t.Fatalf("grant %d %s", rec.Code, rec.Body)
	}
	if rec := call(f.h, http.MethodGet, f.path("/files/"+fileID), nil, &reader); rec.Code != http.StatusOK {
		t.Fatalf("granted download %d", rec.Code)
	}
	if _, rec := f.upload(&reader, accountID, blob); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("reader upload %d", rec.Code)
	}
	if rec := call(f.h, http.MethodDelete, f.path("/files/"+fileID), nil, &reader); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("reader delete %d", rec.Code)
	}

	// Someone outside the vault gets nothing.
	outsider := f.srv.addUser(t, f.q, f.org.ID, "admin", "active")
	approveKey(t, f.q, outsider.user.ID)
	if rec := call(f.h, http.MethodGet, f.path("/files/"+fileID), nil, &outsider); rec.Code != http.StatusNotFound {
		t.Fatalf("outsider download %d", rec.Code)
	}

	// No CSRF token, no change.
	noCSRF := f.owner
	noCSRF.csrf = "wrong"
	if _, rec := f.upload(&noCSRF, accountID, blob); rec.Code != http.StatusForbidden {
		t.Fatalf("upload without csrf %d", rec.Code)
	}

	if rec := call(f.h, http.MethodDelete, f.path("/files/"+fileID), nil, &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("delete %d %s", rec.Code, rec.Body)
	}
	if rec := call(f.h, http.MethodGet, f.path("/files/"+fileID), nil, &f.owner); rec.Code != http.StatusNotFound {
		t.Fatalf("download after delete %d", rec.Code)
	}
}

func TestAccountFileLimits(t *testing.T) {
	f := newVaultFixture(t)
	_, accountID := f.fileAccount(t)
	if rec := rawCall(f.h, http.MethodPost, f.path("/files?id="+uuid.NewString()+"&account="+accountID), "application/pdf", randomBlob(t, 100), &f.owner); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("plain content type %d", rec.Code)
	}
	if _, rec := f.upload(&f.owner, accountID, randomBlob(t, fileOverhead)); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty file %d", rec.Code)
	}
	if _, rec := f.upload(&f.owner, accountID, randomBlob(t, MaxFileBytes+fileOverhead+1)); rec.Code != http.StatusRequestEntityTooLarge || errorCode(rec.Body.String()) != "file_too_large" {
		t.Fatalf("oversize %d %s", rec.Code, rec.Body)
	}
	if _, rec := f.upload(&f.owner, accountID, randomBlob(t, MaxFileBytes+fileOverhead)); rec.Code != http.StatusCreated {
		t.Fatalf("largest allowed %d %s", rec.Code, rec.Body)
	}
	if _, rec := f.upload(&f.owner, uuid.NewString(), randomBlob(t, 100)); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown account %d", rec.Code)
	}
	for i := 1; i < maxFilesAccount; i++ {
		if _, rec := f.upload(&f.owner, accountID, randomBlob(t, 100)); rec.Code != http.StatusCreated {
			t.Fatalf("file %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if _, rec := f.upload(&f.owner, accountID, randomBlob(t, 100)); rec.Code != http.StatusConflict || errorCode(rec.Body.String()) != "too_many_files" {
		t.Fatalf("21st file %d %s", rec.Code, rec.Body)
	}
	// Deleting the account deletes its files.
	if rec := call(f.h, http.MethodDelete, "/api/v1/accounts/"+accountID, map[string]any{}, &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("delete account %d %s", rec.Code, rec.Body)
	}
	var left int
	if err := f.srv.Pool.QueryRow(context.Background(), "SELECT count(*) FROM vault_files WHERE account_id = $1", accountID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("files left after account delete: %d %v", left, err)
	}
}

// The account form always sends a billing cycle. Without a cost or a date
// that must not invent a zero-cost subscription due today.
func TestAccountSaveWithoutBillingMakesNoSubscription(t *testing.T) {
	f := newVaultFixture(t)
	_, accountID := f.fileAccount(t)
	rec := call(f.h, http.MethodPatch, "/api/v1/accounts/"+accountID, map[string]any{
		"label": "main", "billing_cycle": "monthly", "currency": "USD", "cost": "", "renewal_date": "",
	}, &f.owner)
	if rec.Code != http.StatusOK {
		t.Fatalf("save %d %s", rec.Code, rec.Body)
	}
	var subs int
	if err := f.srv.Pool.QueryRow(context.Background(), "SELECT count(*) FROM subscriptions WHERE account_id = $1", accountID).Scan(&subs); err != nil || subs != 0 {
		t.Fatalf("subscriptions after a save without billing: %d %v", subs, err)
	}
	rec = call(f.h, http.MethodPatch, "/api/v1/accounts/"+accountID, map[string]any{
		"label": "main", "billing_cycle": "monthly", "currency": "USD", "cost": "12.50", "renewal_date": "2026-11-15",
	}, &f.owner)
	if rec.Code != http.StatusOK {
		t.Fatalf("save with billing %d %s", rec.Code, rec.Body)
	}
	if err := f.srv.Pool.QueryRow(context.Background(), "SELECT count(*) FROM subscriptions WHERE account_id = $1", accountID).Scan(&subs); err != nil || subs != 1 {
		t.Fatalf("subscriptions after a save with billing: %d %v", subs, err)
	}
}
