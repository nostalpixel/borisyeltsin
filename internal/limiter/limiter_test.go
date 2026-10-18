package limiter

import (
	"testing"
	"time"
)

func TestAllow(t *testing.T) {
	lim := New(2, time.Minute)
	now := time.Now()
	lim.now = func() time.Time { return now }
	if !lim.Allow("a") || !lim.Allow("a") || lim.Allow("a") {
		t.Fatal("limit")
	}
	if !lim.Allow("b") {
		t.Fatal("other key")
	}
	now = now.Add(time.Minute + time.Second)
	if !lim.Allow("a") {
		t.Fatal("window reset")
	}
}

func TestSweepDropsIdleKeys(t *testing.T) {
	lim := New(5, time.Minute)
	now := time.Now()
	lim.now = func() time.Time { return now }
	for _, key := range []string{"a", "b", "c"} {
		lim.Allow(key)
	}
	now = now.Add(2 * time.Minute)
	lim.Allow("d")
	if len(lim.hits) != 1 {
		t.Fatalf("keys kept: %d", len(lim.hits))
	}
}
