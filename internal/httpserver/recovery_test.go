package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"golang.org/x/crypto/nacl/box"
)

func decodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json %v: %s", err, raw)
	}
	return out
}

func (f vaultFixture) epochStatus(t *testing.T, epoch int32) string {
	t.Helper()
	row, err := f.q.GetEpoch(context.Background(), db.GetEpochParams{OrganizationID: f.org.ID, Epoch: epoch})
	if err != nil {
		t.Fatal(err)
	}
	return row.Status
}

func (f vaultFixture) ready(t *testing.T) bool {
	t.Helper()
	rec := call(f.h, http.MethodGet, "/api/v1/recovery", nil, &f.owner)
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery %d %s", rec.Code, rec.Body.String())
	}
	return decodeJSON(t, rec.Body.Bytes())["recovery_ready"].(bool)
}

// epochBody is a setup request with boxed shares the server cannot read.
func (f vaultFixture) epochBody(t *testing.T, custodians ...uuid.UUID) map[string]any {
	t.Helper()
	public, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	list := []map[string]any{}
	for i, id := range custodians {
		ident, err := f.q.GetCryptoIdentity(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, map[string]any{
			"user_id": id.String(), "share_index": i + 1, "fingerprint": ident.Fingerprint,
			"nonce": b64(24), "share_ciphertext": b64(300),
		})
	}
	last, err := f.q.MaxEpoch(context.Background(), f.org.ID)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"epoch": last + 1, "public_key": base64.StdEncoding.EncodeToString(public[:]), "custodians": list}
}

func TestRecoverySetupNeedsTwoDistinctConfirmedCustodiansAndAnEnvelope(t *testing.T) {
	f := newVaultFixture(t)
	other := f.member(t, "member")

	for name, body := range map[string]map[string]any{
		"same user twice": f.epochBody(t, other.user.ID, other.user.ID),
		"one custodian":   f.epochBody(t, other.user.ID),
	} {
		if rec := call(f.h, http.MethodPost, "/api/v1/recovery/epochs", body, &f.owner); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	bad := f.epochBody(t, f.owner.user.ID, other.user.ID)
	bad["custodians"].([]map[string]any)[1]["fingerprint"] = fingerprint(make([]byte, 32))
	if rec := call(f.h, http.MethodPost, "/api/v1/recovery/epochs", bad, &f.owner); errorCode(rec.Body.String()) != "fingerprint_mismatch" {
		t.Fatalf("wrong fingerprint %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(f.h, http.MethodPost, "/api/v1/recovery/epochs", f.epochBody(t, f.owner.user.ID, other.user.ID), &other); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin setup %d %s", rec.Code, rec.Body.String())
	}

	stale := f.epochBody(t, f.owner.user.ID, other.user.ID)
	stale["epoch"] = f.recovery.epoch
	if rec := call(f.h, http.MethodPost, "/api/v1/recovery/epochs", stale, &f.owner); errorCode(rec.Body.String()) != "recovery_epoch_changed" {
		t.Fatalf("shares boxed for a used epoch number %d %s", rec.Code, rec.Body.String())
	}
	rec := call(f.h, http.MethodPost, "/api/v1/recovery/epochs", f.epochBody(t, f.owner.user.ID, other.user.ID), &f.owner)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup %d %s", rec.Code, rec.Body.String())
	}
	created := decodeJSON(t, rec.Body.Bytes())
	epoch := int32(created["epoch"].(float64))
	fp := created["fingerprint"].(string)
	if f.epochStatus(t, epoch) != "pending" || !f.ready(t) {
		t.Fatal("a pending epoch must leave the current one in charge")
	}

	share := call(f.h, http.MethodGet, "/api/v1/recovery/share?epoch="+itoa(epoch), nil, &other)
	if share.Code != http.StatusOK || decodeJSON(t, share.Body.Bytes())["creator_fingerprint"] == "" {
		t.Fatalf("share %d %s", share.Code, share.Body.String())
	}
	if rec := call(f.h, http.MethodGet, "/api/v1/recovery/share?epoch="+itoa(epoch), nil, &f.custodian); rec.Code != http.StatusNotFound {
		t.Fatalf("someone else's share %d", rec.Code)
	}
	confirm := func(a *actor, fingerprint string) *http.Response {
		return call(f.h, http.MethodPost, "/api/v1/recovery/confirm", map[string]any{"epoch": epoch, "fingerprint": fingerprint}, a).Result()
	}
	if res := confirm(&other, fingerprint(make([]byte, 32))); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("confirm with a different key %d", res.StatusCode)
	}
	if res := confirm(&f.custodian, fp); res.StatusCode != http.StatusNotFound {
		t.Fatalf("confirm by a non-custodian %d", res.StatusCode)
	}
	if res := confirm(&other, fp); res.StatusCode != http.StatusOK {
		t.Fatalf("first confirm %d", res.StatusCode)
	}
	if f.epochStatus(t, epoch) != "pending" {
		t.Fatal("one confirmation must not confirm the epoch")
	}
	if res := confirm(&f.owner, fp); res.StatusCode != http.StatusOK {
		t.Fatalf("second confirm %d", res.StatusCode)
	}
	if f.epochStatus(t, epoch) != "confirmed" {
		t.Fatalf("status %s after both confirmed", f.epochStatus(t, epoch))
	}

	// Sealing to the old epoch is refused once a newer one is waiting.
	rec = call(f.h, http.MethodPost, f.path("/recovery-envelope"), map[string]any{
		"epoch": f.recovery.epoch, "ciphertext": b64(160), "expected_key_version": 1,
	}, &f.owner)
	if errorCode(rec.Body.String()) != "recovery_epoch_changed" {
		t.Fatalf("seal to old epoch %d %s", rec.Code, rec.Body.String())
	}
	rec = call(f.h, http.MethodPost, f.path("/recovery-envelope"), map[string]any{
		"epoch": epoch, "ciphertext": b64(160), "expected_key_version": 1,
	}, &f.owner)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate %d %s", rec.Code, rec.Body.String())
	}
	if f.epochStatus(t, epoch) != "active" || f.epochStatus(t, f.recovery.epoch) != "retired" {
		t.Fatalf("after activation: new %s, old %s", f.epochStatus(t, epoch), f.epochStatus(t, f.recovery.epoch))
	}
	env, err := f.q.GetRecoveryEnvelope(context.Background(), db.GetRecoveryEnvelopeParams{VaultID: uuid.MustParse(f.vaultID), KeyVersion: 1})
	if err != nil || env.Epoch != epoch {
		t.Fatalf("envelope epoch %d err %v", env.Epoch, err)
	}
	f.createItem(t, &f.owner, 1)
}

// challenge asks for a challenge and opens it with the recovery private key.
func (f vaultFixture) challenge(t *testing.T, a *actor, key recoveryKey) (string, []byte) {
	t.Helper()
	rec := call(f.h, http.MethodPost, "/api/v1/recovery/challenge", map[string]any{"vault_id": f.vaultID}, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge %d %s", rec.Code, rec.Body.String())
	}
	out := decodeJSON(t, rec.Body.Bytes())
	sealed, _ := base64.StdEncoding.DecodeString(out["sealed"].(string))
	plain, ok := box.OpenAnonymous(nil, sealed, key.public, key.private)
	if !ok {
		t.Fatal("challenge does not open with the recovery key")
	}
	var fields challengePlaintext
	if err := json.Unmarshal(plain, &fields); err != nil {
		t.Fatal(err)
	}
	if fields.ChallengeID.String() != out["challenge_id"] || fields.VaultID.String() != f.vaultID ||
		fields.OrgID != f.org.ID || fields.Epoch != key.epoch || fields.CustodianID != a.user.ID {
		t.Fatalf("challenge fields %+v", fields)
	}
	return out["challenge_id"].(string), plain
}

func (f vaultFixture) grant(a *actor, id string, response []byte) (int, string) {
	rec := call(f.h, http.MethodPost, "/api/v1/recovery/grant", map[string]any{
		"challenge_id": id, "response": base64.StdEncoding.EncodeToString(response),
	}, a)
	return rec.Code, rec.Body.String()
}

func TestChallengeProvesTheRecoveryKeyOnce(t *testing.T) {
	f := newVaultFixture(t)
	outsider := f.member(t, "member")
	if rec := call(f.h, http.MethodPost, "/api/v1/recovery/challenge", map[string]any{"vault_id": f.vaultID}, &outsider); rec.Code != http.StatusForbidden {
		t.Fatalf("non-custodian challenge %d %s", rec.Code, rec.Body.String())
	}

	id, plain := f.challenge(t, &f.custodian, f.recovery)
	wrong := append([]byte(nil), plain...)
	wrong[len(wrong)-3] ^= 1
	if code, body := f.grant(&f.custodian, id, wrong); code != http.StatusForbidden || errorCode(body) != "challenge_failed" {
		t.Fatalf("wrong answer %d %s", code, body)
	}
	if code, body := f.grant(&f.custodian, id, plain); code != http.StatusForbidden || errorCode(body) != "challenge_invalid" {
		t.Fatalf("a failed challenge must stay used: %d %s", code, body)
	}

	id, plain = f.challenge(t, &f.custodian, f.recovery)
	if code, body := f.grant(&f.owner, id, plain); code != http.StatusForbidden {
		t.Fatalf("someone else's challenge %d %s", code, body)
	}
	if code, body := f.grant(&f.custodian, id, plain); code != http.StatusOK {
		t.Fatalf("grant %d %s", code, body)
	}
	if code, body := f.grant(&f.custodian, id, plain); code != http.StatusForbidden || errorCode(body) != "challenge_invalid" {
		t.Fatalf("replayed answer %d %s", code, body)
	}

	id, plain = f.challenge(t, &f.custodian, f.recovery)
	if _, err := f.srv.Pool.Exec(context.Background(), `UPDATE recovery_challenges SET expires_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if code, body := f.grant(&f.custodian, id, plain); code != http.StatusForbidden || errorCode(body) != "challenge_invalid" {
		t.Fatalf("expired challenge %d %s", code, body)
	}

	// Three challenges so far this hour; five are allowed, the sixth is not.
	f.challenge(t, &f.custodian, f.recovery)
	f.challenge(t, &f.custodian, f.recovery)
	rec := call(f.h, http.MethodPost, "/api/v1/recovery/challenge", map[string]any{"vault_id": f.vaultID}, &f.custodian)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth challenge %d %s", rec.Code, rec.Body.String())
	}
}

func TestRecoveryRotationMakesTheCustodianAnOwnerAndSpendsTheKey(t *testing.T) {
	f := newVaultFixture(t)
	id, version := f.createItem(t, &f.owner, 1)
	editor := f.member(t, "member")
	f.envelope(t, &f.owner, editor.user.ID, 1, http.StatusOK)

	if rec := call(f.h, http.MethodGet, f.path("/items"), nil, &f.custodian); rec.Code == http.StatusOK {
		t.Fatal("a custodian without a grant read the items")
	}
	challengeID, plain := f.challenge(t, &f.custodian, f.recovery)
	if code, body := f.grant(&f.custodian, challengeID, plain); code != http.StatusOK {
		t.Fatalf("grant %d %s", code, body)
	}
	for _, path := range []string{"", "/items", "/recovery-envelope"} {
		if rec := call(f.h, http.MethodGet, f.path(path), nil, &f.custodian); rec.Code != http.StatusOK {
			t.Fatalf("grant read %q %d %s", path, rec.Code, rec.Body.String())
		}
	}

	items := []map[string]any{{"id": id, "version": version, "nonce": b64(24), "ciphertext": b64(40)}}
	envelope := func(ids ...uuid.UUID) []map[string]any {
		out := []map[string]any{}
		for _, uid := range ids {
			ident, _ := f.q.GetCryptoIdentity(context.Background(), uid)
			out = append(out, map[string]any{"user_id": uid.String(), "fingerprint": ident.Fingerprint, "ciphertext": b64(80)})
		}
		return out
	}
	rotate := func(envs []map[string]any, recovery map[string]any) (int, string) {
		rec := call(f.h, http.MethodPost, f.path("/rotation"), map[string]any{
			"expected_key_version": 1, "items": items, "envelopes": envs, "recovery": recovery,
		}, &f.custodian)
		return rec.Code, rec.Body.String()
	}
	if code, body := rotate(envelope(f.owner.user.ID), map[string]any{}); code != http.StatusBadRequest || errorCode(body) != "envelope_set" {
		t.Fatalf("recovery rotation without the custodian %d %s", code, body)
	}
	if code, body := rotate(envelope(f.custodian.user.ID), map[string]any{"epoch": f.recovery.epoch, "ciphertext": b64(160)}); code != http.StatusBadRequest {
		t.Fatalf("recovery rotation resealing to the used key %d %s", code, body)
	}
	// Keep the editor, drop the owner whose key was lost.
	if code, body := rotate(envelope(f.custodian.user.ID, editor.user.ID), map[string]any{}); code != http.StatusOK {
		t.Fatalf("recovery rotation %d %s", code, body)
	}

	member, err := f.q.GetVaultMember(context.Background(), db.GetVaultMemberParams{VaultID: uuid.MustParse(f.vaultID), UserID: f.custodian.user.ID})
	if err != nil || member.Role != "owner" {
		t.Fatalf("custodian membership %+v %v", member, err)
	}
	if _, err := f.q.GetVaultMember(context.Background(), db.GetVaultMemberParams{VaultID: uuid.MustParse(f.vaultID), UserID: f.owner.user.ID}); err == nil {
		t.Fatal("the left-out owner is still a member")
	}
	if f.epochStatus(t, f.recovery.epoch) != "spent" || f.ready(t) {
		t.Fatal("a used recovery key must be spent")
	}
	if rec := call(f.h, http.MethodPost, "/api/v1/recovery/challenge", map[string]any{"vault_id": f.vaultID}, &f.custodian); errorCode(rec.Body.String()) != "recovery_unavailable" {
		t.Fatalf("challenge on a spent key %d %s", rec.Code, rec.Body.String())
	}
	rec := call(f.h, http.MethodPost, f.path("/items"), map[string]any{
		"id": uuid.NewString(), "nonce": b64(24), "ciphertext": b64(40), "expected_key_version": 2,
	}, &f.custodian)
	if errorCode(rec.Body.String()) != "recovery_not_ready" {
		t.Fatalf("new item after recovery %d %s", rec.Code, rec.Body.String())
	}
	// The custodian is now an ordinary key-holding owner.
	if code, body := f.rotation(&f.custodian, 2, []map[string]any{{"id": id, "version": version + 1, "nonce": b64(24), "ciphertext": b64(40)}},
		[]uuid.UUID{f.custodian.user.ID, editor.user.ID}); code != http.StatusOK {
		t.Fatalf("owner rotation after recovery %d %s", code, body)
	}
}

func TestDepartureDegradesRecovery(t *testing.T) {
	cases := map[string]func(f vaultFixture) int{
		"custodian revoked": func(f vaultFixture) int {
			return call(f.h, http.MethodPost, "/api/v1/users/"+f.custodian.user.ID.String()+"/revoke", map[string]any{}, &f.owner).Code
		},
		"custodian key replaced": func(f vaultFixture) int {
			if rec := call(f.h, http.MethodPost, "/api/v1/crypto/identity", fakeIdentity(), &f.custodian); rec.Code != http.StatusOK {
				return rec.Code
			}
			return call(f.h, http.MethodPost, "/api/v1/crypto/users/"+f.custodian.user.ID.String()+"/approve", map[string]any{}, &f.owner).Code
		},
	}
	for name, depart := range cases {
		t.Run(name, func(t *testing.T) {
			f := newVaultFixture(t)
			if code := depart(f); code != http.StatusOK {
				t.Fatalf("departure %d", code)
			}
			if f.epochStatus(t, f.recovery.epoch) != "degraded" || f.ready(t) {
				t.Fatal("recovery must be degraded")
			}
			vault, err := f.q.GetVault(context.Background(), db.GetVaultParams{ID: uuid.MustParse(f.vaultID), OrganizationID: f.org.ID})
			if err != nil || !vault.RotationRequired {
				t.Fatal("vault must need rotation")
			}
			rec := call(f.h, http.MethodPost, f.path("/items"), map[string]any{
				"id": uuid.NewString(), "nonce": b64(24), "ciphertext": b64(40), "expected_key_version": 1,
			}, &f.owner)
			if errorCode(rec.Body.String()) != "recovery_not_ready" {
				t.Fatalf("new item while degraded %d %s", rec.Code, rec.Body.String())
			}
			if rec := call(f.h, http.MethodPost, "/api/v1/recovery/challenge", map[string]any{"vault_id": f.vaultID}, &f.owner); errorCode(rec.Body.String()) != "recovery_unavailable" {
				t.Fatalf("challenge while degraded %d %s", rec.Code, rec.Body.String())
			}
			// The owner can still rotate; nothing is sealed to the degraded key.
			if code, body := f.rotation(&f.owner, 1, []map[string]any{}, []uuid.UUID{f.owner.user.ID}); code != http.StatusOK {
				t.Fatalf("rotation while degraded %d %s", code, body)
			}
		})
	}
}

func TestRevokingTheEpochCreatorDegradesRecovery(t *testing.T) {
	f := newVaultFixture(t)
	creator := f.srv.addUser(t, f.q, f.org.ID, "admin", "active")
	approveKey(t, f.q, creator.user.ID)
	key := seedRecovery(t, f.q, f.org.ID, creator.user.ID, f.owner.user.ID, f.custodian.user.ID)
	if rec := call(f.h, http.MethodPost, "/api/v1/users/"+creator.user.ID.String()+"/revoke", map[string]any{}, &f.owner); rec.Code != http.StatusOK {
		t.Fatalf("revoke %d %s", rec.Code, rec.Body.String())
	}
	if f.epochStatus(t, key.epoch) != "degraded" {
		t.Fatalf("status %s", f.epochStatus(t, key.epoch))
	}
}

// libsodiumSealed is crypto_box_seal("borisyeltsin recovery vector") to
// libsodiumPublic, made once with libsodium-wrappers-sumo 0.7.15, the browser's
// library. It proves Go opens what the browser seals. web/src/crypto/vault.test.ts
// opens a box Go sealed to the same key pair.
const (
	libsodiumPublic  = "iljxAgbEX8kwDZbw9YWYBO9QckcDAjDA7iEsWPIStlk="
	libsodiumPrivate = "q/HDD5h1F1Q0Lpm1sjV6bvibyh4+Wuw1jn8JhTYemnI="
	libsodiumSealed  = "KeIPEkoGE5ONd2pPuXSdd85AYOqWjxCvBc/lMVVxuHj7+l3KEUXkDd58nnVp27NcEZ79dahpqJY4JoeSN7lsdPSHL2k77AmeDhg57g=="
)

func TestGoOpensLibsodiumSealedBoxes(t *testing.T) {
	var public, private [32]byte
	pub, _ := base64.StdEncoding.DecodeString(libsodiumPublic)
	priv, _ := base64.StdEncoding.DecodeString(libsodiumPrivate)
	sealed, _ := base64.StdEncoding.DecodeString(libsodiumSealed)
	copy(public[:], pub)
	copy(private[:], priv)
	plain, ok := box.OpenAnonymous(nil, sealed, &public, &private)
	if !ok || string(plain) != "borisyeltsin recovery vector" {
		t.Fatalf("open %v %q", ok, plain)
	}
}

func TestGrantIsBoundToItsVaultExpiresAndWorksOnce(t *testing.T) {
	f := newVaultFixture(t)
	id, plain := f.challenge(t, &f.custodian, f.recovery)
	if code, body := f.grant(&f.custodian, id, plain); code != http.StatusOK {
		t.Fatalf("grant %d %s", code, body)
	}
	// A second vault of the same organization, inserted directly (the API
	// allows one), is not covered by a grant for the first.
	other, err := f.q.CreateVault(context.Background(), db.CreateVaultParams{OrganizationID: f.org.ID, Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(f.h, http.MethodGet, "/api/v1/vaults/"+other.ID.String()+"/items", nil, &f.custodian); rec.Code == http.StatusOK {
		t.Fatal("a grant opened another vault")
	}
	if rec := call(f.h, http.MethodGet, f.path("/items"), nil, &f.custodian); rec.Code != http.StatusOK {
		t.Fatalf("grant read %d", rec.Code)
	}
	if _, err := f.srv.Pool.Exec(context.Background(), `UPDATE recovery_grants SET expires_at = now() - interval '1 second' WHERE custodian_id = $1`, f.custodian.user.ID); err != nil {
		t.Fatal(err)
	}
	if rec := call(f.h, http.MethodGet, f.path("/items"), nil, &f.custodian); rec.Code == http.StatusOK {
		t.Fatal("an expired grant still reads the vault")
	}
	if code, body := f.rotation(&f.custodian, 1, []map[string]any{}, []uuid.UUID{f.custodian.user.ID}); code == http.StatusOK {
		t.Fatalf("an expired grant rotated: %s", body)
	}

	// A fresh grant rotates once; afterwards it reads nothing more.
	id, plain = f.challenge(t, &f.custodian, f.recovery)
	if code, body := f.grant(&f.custodian, id, plain); code != http.StatusOK {
		t.Fatalf("second grant %d %s", code, body)
	}
	ident, _ := f.q.GetCryptoIdentity(context.Background(), f.custodian.user.ID)
	rec := call(f.h, http.MethodPost, f.path("/rotation"), map[string]any{
		"expected_key_version": 1, "items": []map[string]any{}, "recovery": map[string]any{},
		"envelopes": []map[string]any{{"user_id": f.custodian.user.ID.String(), "fingerprint": ident.Fingerprint, "ciphertext": b64(80)}},
	}, &f.custodian)
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery rotation %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := liveGrant(context.Background(), f.q, Principal{UserID: f.custodian.user.ID, OrgID: f.org.ID}, uuid.MustParse(f.vaultID)); ok {
		t.Fatal("the grant survived its rotation")
	}
}
