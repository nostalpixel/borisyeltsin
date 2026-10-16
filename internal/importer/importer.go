// Package importer reads a version-1 backup from the original services ledger.
// Password values are refused. The browser encrypts those before calling the API.
package importer

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/nostalpixel/borisyeltsin/internal/fieldsafe"
)

const (
	maxServices = 500
	maxAccounts = 200
)

// Account is non-secret account metadata. Cost is a decimal string.
type Account struct {
	Label    string `json:"label"`
	Login    string `json:"login"`
	Cost     string `json:"cost"`
	Currency string `json:"currency"`
	Date     string `json:"date"`
	Card     string `json:"card"`
	Notes    string `json:"notes"`
}

// Service is one imported service.
type Service struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Unclear     bool      `json:"unclear"`
	Logo        string    `json:"logo"`
	Bg          string    `json:"bg"`
	Fg          string    `json:"fg"`
	Accounts    []Account `json:"accounts"`
}

var categories = map[string]struct{}{
	"infra": {}, "domains": {}, "tools": {}, "comms": {}, "partners": {}, "payments": {}, "other": {},
}

var currencies = map[string]struct{}{
	"USD": {}, "EUR": {}, "RUB": {}, "GBP": {}, "USDT": {},
}

// Parse decodes a version-1 backup into non-secret services.
func Parse(raw []byte) ([]Service, error) {
	if err := fieldsafe.RejectSecrets(raw); err != nil {
		return nil, err
	}
	var doc struct {
		Version  int `json:"version"`
		Services []struct {
			Name        string `json:"name"`
			URL         string `json:"url"`
			Category    string `json:"category"`
			Description string `json:"description"`
			Unclear     bool   `json:"unclear"`
			Logo        string `json:"logo"`
			Bg          string `json:"bg"`
			Fg          string `json:"fg"`
			Accounts    []struct {
				Label    string `json:"label"`
				Login    string `json:"login"`
				Cost     any    `json:"cost"`
				Currency string `json:"currency"`
				Date     string `json:"date"`
				Card     string `json:"card"`
				Notes    string `json:"notes"`
			} `json:"accounts"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Version != 1 || len(doc.Services) > maxServices {
		return nil, errString("invalid_backup")
	}
	out := make([]Service, 0, len(doc.Services))
	for _, src := range doc.Services {
		name := clip(src.Name, 160)
		if name == "" || len(src.Accounts) > maxAccounts {
			return nil, errString("invalid_service")
		}
		category := src.Category
		if _, ok := categories[category]; !ok {
			category = "other"
		}
		item := Service{
			Name:        name,
			URL:         safeURL(clip(src.URL, 500)),
			Category:    category,
			Description: clip(src.Description, 200),
			Unclear:     src.Unclear,
			Logo:        clip(src.Logo, 3),
			Bg:          colorOr(src.Bg, "#eeeafc"),
			Fg:          colorOr(src.Fg, "#7663c6"),
		}
		if item.Logo == "" {
			item.Logo = strings.ToUpper(clip(name, 2))
		}
		for i, acc := range src.Accounts {
			cost := costString(acc.Cost)
			if cost != "" && !validCost(cost) {
				return nil, errString("invalid_cost")
			}
			date := clip(acc.Date, 10)
			if date != "" {
				if _, err := time.Parse("2006-01-02", date); err != nil {
					return nil, errString("invalid_date")
				}
			}
			currency := acc.Currency
			if _, ok := currencies[currency]; !ok {
				currency = "USD"
			}
			label := clip(acc.Label, 80)
			if label == "" {
				label = "Account"
				if i >= 0 {
					label = clip(label, 80)
				}
			}
			card := clip(acc.Card, 80)
			notes := clip(acc.Notes, 5000)
			login := clip(acc.Login, 500)
			if err := fieldsafe.ScreenText(card, notes, item.Description, item.Name, login); err != nil {
				return nil, err
			}
			item.Accounts = append(item.Accounts, Account{
				Label: label, Login: login, Cost: cost, Currency: currency, Date: date, Card: card, Notes: notes,
			})
		}
		out = append(out, item)
	}
	return out, nil
}

func costString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == 0 {
			return "0"
		}
		return strings.TrimRight(strings.TrimRight(trimFloat(typed), "0"), ".")
	default:
		return ""
	}
}

func trimFloat(value float64) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(raw)
}

func validCost(raw string) bool {
	if raw == "" {
		return false
	}
	dot := false
	frac := 0
	for i, r := range raw {
		if r == '.' && !dot && i > 0 {
			dot = true
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
		if dot {
			frac++
			if frac > 2 {
				return false
			}
		}
	}
	return true
}

func clip(value string, max int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > max {
		return string(runes[:max])
	}
	return value
}

func colorOr(value, fallback string) string {
	if len(value) == 7 && value[0] == '#' {
		for _, r := range value[1:] {
			switch {
			case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			default:
				return fallback
			}
		}
		return strings.ToLower(value)
	}
	return fallback
}

func safeURL(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		return raw
	}
	return ""
}

type errString string

func (e errString) Error() string { return string(e) }
