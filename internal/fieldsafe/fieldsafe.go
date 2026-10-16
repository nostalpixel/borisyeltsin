// Package fieldsafe rejects secret-shaped JSON and primary account numbers.
package fieldsafe

import (
	"bytes"
	"encoding/json"
	"strings"
)

var bannedKeys = map[string]struct{}{
	"password": {}, "passphrase": {}, "secret": {}, "private_key": {}, "privatekey": {},
	"cvv": {}, "cvc": {}, "pan": {}, "recovery_key": {}, "recoverykey": {},
	"vault_key": {}, "vaultkey": {}, "token": {}, "code_verifier": {},
}

// ErrSecret is returned when a payload carries a secret field.
var ErrSecret = errString("secret_field")

// ErrCard is returned when free text contains a primary account number.
var ErrCard = errString("card_number")

type errString string

func (e errString) Error() string { return string(e) }

// RejectSecrets walks JSON and fails when a banned key has a non-empty value.
func RejectSecrets(raw []byte) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return err
	}
	if secretKey(value) {
		return ErrSecret
	}
	return nil
}

func secretKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if _, banned := bannedKeys[strings.ToLower(key)]; banned && present(child) {
				return true
			}
			if secretKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if secretKey(child) {
				return true
			}
		}
	}
	return false
}

func present(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	default:
		return true
	}
}

// ContainsPAN reports whether s contains 13 to 19 digits, ignoring spaces and dashes.
func ContainsPAN(s string) bool {
	digits := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			if digits >= 13 && digits <= 19 {
				// Keep scanning so a longer digit run is still rejected.
				if digits >= 13 {
					return true
				}
			}
		case r == ' ' || r == '-':
		default:
			digits = 0
		}
	}
	return false
}

// ScreenText rejects PAN-shaped free text.
func ScreenText(fields ...string) error {
	for _, field := range fields {
		if ContainsPAN(field) {
			return ErrCard
		}
	}
	return nil
}
