package token

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
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

func TestNewInvite(t *testing.T) {
	if len(words) != 7772 {
		t.Fatalf("word list has %d words", len(words))
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		plain, hash, err := NewInvite()
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(plain, "-")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			t.Fatalf("not a word pair: %q", plain)
		}
		if NormalizeInvite(plain) != plain {
			t.Fatalf("%q is not in normal form", plain)
		}
		if !Equal(hash, Hash(plain)) {
			t.Fatal("stored hash does not match invitation")
		}
		seen[plain] = true
	}
	if len(seen) < 190 {
		t.Fatalf("only %d distinct invitations in 200", len(seen))
	}
}

func TestNormalizeInvite(t *testing.T) {
	legacy, _, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"eggs-watermelon":      "eggs-watermelon",
		"  Eggs Watermelon \n": "eggs-watermelon",
		"EGGS--watermelon":     "eggs-watermelon",
		"eggs_watermelon":      "eggs-watermelon",
		" " + legacy + " ":     legacy,
	} {
		if got := NormalizeInvite(in); got != want {
			t.Errorf("NormalizeInvite(%q) = %q, want %q", in, got, want)
		}
	}
}
