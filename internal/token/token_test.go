package token

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestInviteTTL(t *testing.T) {
	if InviteTTL != 24*time.Hour {
		t.Fatalf("ttl = %s", InviteTTL)
	}
}

func TestHashKnownValue(t *testing.T) {
	sum := sha256.Sum256([]byte("abc"))
	got := Hash("abc")
	if string(got) != string(sum[:]) {
		t.Fatal("hash mismatch")
	}
}

func TestNewToken(t *testing.T) {
	plain, hash, err := New()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("len %d", len(raw))
	}
	if !Equal(hash, Hash(plain)) {
		t.Fatal("stored hash does not match token")
	}
	other, _, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if Equal(hash, Hash(other)) {
		t.Fatal("tokens collided")
	}
}
