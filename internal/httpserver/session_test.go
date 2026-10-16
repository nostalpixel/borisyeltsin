package httpserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	dbschema "github.com/nostalpixel/borisyeltsin/db"
	"github.com/nostalpixel/borisyeltsin/internal/config"
	dbq "github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/migrate"
	"github.com/nostalpixel/borisyeltsin/internal/testpg"
	"github.com/nostalpixel/borisyeltsin/internal/token"
)

func TestSessionTokenIsStoredHashed(t *testing.T) {
	srv, q := newServer(t)
	h := srv.Handler()
	org, err := q.CreateOrganization(context.Background(), "Hash")
	if err != nil {
		t.Fatal(err)
	}
	plain, hash, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateInvitation(context.Background(), dbq.CreateInvitationParams{
		OrganizationID: org.ID, TokenHash: hash, IntendedIssuer: "https://idp.example",
		IntendedSubject: "hash-subject", IntendedEmail: "h@example.com", Role: "member",
		ExpiresAt: time.Now().Add(token.InviteTTL),
	}); err != nil {
		t.Fatal(err)
	}
	cookie, code := srv.finishLogin(context.Background(), identityClaims{
		Issuer: "https://idp.example", Subject: "hash-subject", AMR: []string{"mfa"},
	}, token.Hash(plain))
	if code != "" {
		t.Fatal(code)
	}
	var stored []byte
	if err := srv.Pool.QueryRow(context.Background(),
		"SELECT s.token_hash FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.subject = 'hash-subject'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stored, []byte(cookie)) || !bytes.Equal(stored, token.Hash(cookie)) {
		t.Fatal("session row does not hold the SHA-256 of the cookie")
	}
	get := func(value string) int {
		return call(h, http.MethodGet, "/api/v1/session", nil, &actor{cookie: &http.Cookie{Name: "be_session", Value: value}}).Code
	}
	if code := get(cookie); code != http.StatusOK {
		t.Fatalf("cookie login %d", code)
	}
	if code := get(encodeB64(stored)); code != http.StatusUnauthorized {
		t.Fatalf("stored hash used as cookie %d", code)
	}
}

func bootstrapConfig() config.Config {
	cfg := config.Config{}
	cfg.Bootstrap.OrgName = "First"
	cfg.Bootstrap.Issuer = "https://idp.example"
	cfg.Bootstrap.Subject = "first-admin"
	cfg.Bootstrap.Email = "first@example.com"
	return cfg
}

func TestBootstrapKeepsOneLiveInvite(t *testing.T) {
	pool := testpg.EmptyDatabase(t)
	ctx := context.Background()
	if err := migrate.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	cfg := bootstrapConfig()
	var wg sync.WaitGroup
	tokens := make([]string, 4)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			plain, err := Bootstrap(ctx, pool, cfg)
			if err != nil {
				t.Error(err)
			}
			tokens[i] = plain
		}(i)
	}
	wg.Wait()
	var orgs, open int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM organizations").Scan(&orgs); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM invitations WHERE revoked_at IS NULL AND accepted_at IS NULL").Scan(&open); err != nil {
		t.Fatal(err)
	}
	if orgs != 1 || open != 1 {
		t.Fatalf("concurrent bootstrap: %d organizations, %d open invites", orgs, open)
	}
	last, err := Bootstrap(ctx, pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(pool, config.Config{MFAAMR: []string{"mfa"}, SessionTTL: time.Hour})
	for _, old := range tokens {
		if _, code := srv.finishLogin(ctx, identityClaims{Issuer: cfg.Bootstrap.Issuer, Subject: cfg.Bootstrap.Subject, AMR: []string{"mfa"}}, token.Hash(old)); code == "" {
			t.Fatal("a replaced bootstrap token still logs in")
		}
	}
	if _, code := srv.finishLogin(ctx, identityClaims{Issuer: cfg.Bootstrap.Issuer, Subject: cfg.Bootstrap.Subject, AMR: []string{"mfa"}}, token.Hash(last)); code != "" {
		t.Fatalf("latest bootstrap token %s", code)
	}
	if _, err := Bootstrap(ctx, pool, cfg); !errors.Is(err, ErrBootstrapClosed) {
		t.Fatalf("bootstrap after the first user: %v", err)
	}
}

func TestBootstrapRacesFirstLogin(t *testing.T) {
	pool := testpg.EmptyDatabase(t)
	ctx := context.Background()
	if err := migrate.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	cfg := bootstrapConfig()
	first, err := Bootstrap(ctx, pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(pool, config.Config{MFAAMR: []string{"mfa"}, SessionTTL: time.Hour})
	var wg sync.WaitGroup
	var loginCode string
	var bootErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, loginCode = srv.finishLogin(ctx, identityClaims{Issuer: cfg.Bootstrap.Issuer, Subject: cfg.Bootstrap.Subject, AMR: []string{"mfa"}}, token.Hash(first))
	}()
	go func() {
		defer wg.Done()
		_, bootErr = Bootstrap(ctx, pool, cfg)
	}()
	wg.Wait()
	// Either the login won (bootstrap is then closed) or bootstrap won
	// (the first token was revoked before it was used). Never both.
	loginWon := loginCode == ""
	bootWon := bootErr == nil
	if loginWon == bootWon {
		t.Fatalf("login=%q bootstrap=%v", loginCode, bootErr)
	}
	var open int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM invitations WHERE revoked_at IS NULL AND accepted_at IS NULL").Scan(&open); err != nil {
		t.Fatal(err)
	}
	if loginWon && open != 0 || bootWon && open != 1 {
		t.Fatalf("open invites %d (login won: %v)", open, loginWon)
	}
}

// TestMigrationFromPopulatedSchema applies 002 on top of a 001 database that
// already has a session, a vault with an envelope and an item.
func TestMigrationFromPopulatedSchema(t *testing.T) {
	pool := testpg.EmptyDatabase(t)
	ctx := context.Background()
	initSQL, err := dbschema.Migrations.ReadFile("migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"CREATE TABLE schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
		string(initSQL),
		"INSERT INTO schema_migrations (version) VALUES ('001_init.sql')",
		"INSERT INTO organizations (id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'Old')",
		`INSERT INTO users (id, organization_id, issuer, subject, email, status)
		 VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'https://idp', 'old', 'o@example.com', 'active')`,
		`INSERT INTO sessions (id, user_id, csrf_secret, expires_at)
		 VALUES ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000002', 'x', now() + interval '1 hour')`,
		`INSERT INTO vaults (id, organization_id, name) VALUES ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000001', 'Used')`,
		`INSERT INTO vaults (id, organization_id, name) VALUES ('00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000001', 'Fresh')`,
		`INSERT INTO vault_key_envelopes (vault_id, user_id, key_version, recipient_fingerprint, ciphertext, created_by)
		 VALUES ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000002', 1, 'fp', '\x00', '00000000-0000-0000-0000-000000000002')`,
		`INSERT INTO vault_items (id, vault_id, key_version, nonce, ciphertext, created_by, updated_by)
		 VALUES ('00000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000004', 1, '\x00', '\x00',
		         '00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%v: %s", err, stmt[:40])
		}
	}
	if err := migrate.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var sessions, version int
	var used, fresh bool
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM sessions").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT version FROM vault_items").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT initialized FROM vaults WHERE name = 'Used'").Scan(&used); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT initialized FROM vaults WHERE name = 'Fresh'").Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || version != 1 || !used || fresh {
		t.Fatalf("after 002: sessions=%d version=%d used=%v fresh=%v", sessions, version, used, fresh)
	}
}

func TestCSVCellsCannotBeFormulas(t *testing.T) {
	rows := csvSafe([][]string{{"=HYPERLINK(\"x\")", "+1", "-2", "@SUM(A1)", "plain", ""}})
	want := []string{"'=HYPERLINK(\"x\")", "'+1", "'-2", "'@SUM(A1)", "plain", ""}
	for i, cell := range rows[0] {
		if cell != want[i] {
			t.Fatalf("cell %d: %q", i, cell)
		}
	}
}
