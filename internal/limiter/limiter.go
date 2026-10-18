// Package limiter is a per-process sliding-window rate limiter.
package limiter

import (
	"sync"
	"time"
)

// Limiter allows limit events per key inside window.
type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
	now    func() time.Time
	swept  time.Time
}

// New returns a limiter. A non-positive limit denies every event.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		hits:   map[string][]time.Time{},
		now:    time.Now,
	}
}

// Allow reports whether key may proceed and records the event when it may.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	l.sweep(now, cutoff)
	kept := l.hits[key][:0]
	for _, hit := range l.hits[key] {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// sweep drops keys with no hits inside the window, at most once per window,
// so keys from one-off callers do not accumulate.
func (l *Limiter) sweep(now, cutoff time.Time) {
	if now.Sub(l.swept) < l.window {
		return
	}
	l.swept = now
	for key, hits := range l.hits {
		if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
			delete(l.hits, key)
		}
	}
}
