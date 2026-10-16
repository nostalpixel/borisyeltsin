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
