package token

import (
	"bufio"
	"crypto/rand"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
)

//go:embed words.txt
var wordFile string

var words = loadWords(wordFile)

func loadWords(file string) []string {
	out := []string{}
	scanner := bufio.NewScanner(strings.NewReader(file))
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			out = append(out, word)
		}
	}
	return out
}

// legacyInviteLen is the length of the base64 invitations issued before
// word pairs. They are compared exactly, case and all.
const legacyInviteLen = 43

// NewInvite returns two random words joined by a dash, such as
// "eggs-watermelon", and the SHA-256 stored on the server. Two words from
// 7,772 give about 26 bits. That is enough because an invitation is single
// use, expires after InviteTTL and only works for the one identity provider
// subject it was issued to, so guessing it gains nothing for anyone else.
func NewInvite() (string, []byte, error) {
	pair := make([]string, 2)
	for i := range pair {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", nil, fmt.Errorf("read random: %w", err)
		}
		pair[i] = words[n.Int64()]
	}
	plain := strings.Join(pair, "-")
	return plain, Hash(plain), nil
}

// NormalizeInvite turns what a person typed into the stored form: lower
// case, words joined by single dashes, so "Eggs Watermelon" and
// "eggs-watermelon" match. Legacy base64 invitations pass through unchanged.
func NormalizeInvite(typed string) string {
	typed = strings.TrimSpace(typed)
	if len(typed) == legacyInviteLen && !strings.ContainsAny(typed, " \t\r\n") {
		return typed
	}
	parts := strings.FieldsFunc(strings.ToLower(typed), func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	return strings.Join(parts, "-")
}
