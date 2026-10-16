// Package token creates and hashes single-use invitation tokens.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"
)

// InviteTTL is the invitation lifetime required by the product spec.
const InviteTTL = 24 * time.Hour

// New returns a 32-byte token and the SHA-256 hash stored on the server.
func New() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("read random: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	return plain, Hash(plain), nil
}

// Hash returns the SHA-256 of an invitation token. The plaintext is never stored.
func Hash(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}

// Equal compares two hashes in constant time.
func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
