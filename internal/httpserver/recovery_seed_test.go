package httpserver

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"golang.org/x/crypto/nacl/box"
)

// recoveryKey is a real X25519 recovery key pair, so tests can open challenges.
type recoveryKey struct {
	epoch   int32
	public  *[32]byte
	private *[32]byte
}

// seedRecovery stores an active recovery epoch directly, as if both custodians
// had confirmed and an owner had sealed the first envelope. The custodians'
// approved keys must already exist.
func seedRecovery(t *testing.T, q *db.Queries, org, creator, first, second uuid.UUID) recoveryKey {
	t.Helper()
	ctx := context.Background()
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	creatorKey, err := q.GetCryptoIdentity(ctx, creator)
	if err != nil {
		t.Fatal(err)
	}
	last, err := q.MaxEpoch(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RetireCurrentEpoch(ctx, org); err != nil {
		t.Fatal(err)
	}
	epoch, err := q.InsertEpoch(ctx, db.InsertEpochParams{
		OrganizationID: org, Epoch: last + 1, PublicKey: public[:], Fingerprint: fingerprint(public[:]),
		CreatedBy: creator, CreatorPublicKey: creatorKey.PublicKey, CreatorFingerprint: creatorKey.Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, userID := range []uuid.UUID{first, second} {
		ident, err := q.GetCryptoIdentity(ctx, userID)
		if err != nil {
			t.Fatal(err)
		}
		if err := q.InsertCustodian(ctx, db.InsertCustodianParams{
			OrganizationID: org, Epoch: epoch.Epoch, ShareIndex: int16(i + 1), UserID: userID,
			Fingerprint: ident.Fingerprint, ShareNonce: make([]byte, 24), ShareCiphertext: make([]byte, 120),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.ConfirmCustodian(ctx, db.ConfirmCustodianParams{OrganizationID: org, Epoch: epoch.Epoch, UserID: userID}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.SetEpochStatus(ctx, db.SetEpochStatusParams{OrganizationID: org, Epoch: epoch.Epoch, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	return recoveryKey{epoch: epoch.Epoch, public: public, private: private}
}

// recoveryBody is the rotation "recovery" field for the organization's
// current seal target, or nothing when there is none.
func recoveryBody(t *testing.T, q *db.Queries, org uuid.UUID) map[string]any {
	t.Helper()
	target, err := sealTarget(context.Background(), q, org)
	if err != nil {
		t.Fatal(err)
	}
	if target == nil {
		return map[string]any{}
	}
	return map[string]any{"epoch": target.Epoch, "ciphertext": b64(160)}
}
