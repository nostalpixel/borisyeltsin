// Package config loads process configuration from the environment and from
// Docker secret files.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the process configuration.
type Config struct {
	DatabaseURL  string
	HTTPAddr     string
	PublicURL    string
	CookieSecure bool
	TrustProxy   bool
	SessionTTL   time.Duration
	TimeZone     string
	MFAAMR       []string
	OIDC         OIDC
	Bootstrap    Bootstrap
}

// OIDC is the external Authentik client.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// Bootstrap creates the first organization and a single admin invitation.
type Bootstrap struct {
	OrgName string
	Issuer  string
	Subject string
	Email   string
}

// Enabled reports whether bootstrap variables are complete.
func (b Bootstrap) Enabled() bool {
	return b.OrgName != "" && b.Issuer != "" && b.Subject != "" && b.Email != ""
}

// Load reads configuration. DATABASE_URL is required.
func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:  value("DATABASE_URL"),
		HTTPAddr:     envDefault("HTTP_ADDR", ":8080"),
		PublicURL:    strings.TrimRight(envDefault("PUBLIC_URL", "http://localhost:8080"), "/"),
		CookieSecure: envDefault("COOKIE_SECURE", "true") != "false",
		TrustProxy:   envDefault("TRUST_PROXY", "false") == "true",
		TimeZone:     envDefault("ALERT_TIMEZONE", "UTC"),
		MFAAMR:       split(envDefault("OIDC_MFA_AMR", "mfa,otp,totp,webauthn")),
		OIDC: OIDC{
			Issuer:       value("OIDC_ISSUER"),
			ClientID:     value("OIDC_CLIENT_ID"),
			ClientSecret: value("OIDC_CLIENT_SECRET"),
			RedirectURL:  value("OIDC_REDIRECT_URL"),
		},
		Bootstrap: Bootstrap{
			OrgName: value("BOOTSTRAP_ORG_NAME"),
			Issuer:  value("BOOTSTRAP_OIDC_ISSUER"),
			Subject: value("BOOTSTRAP_OIDC_SUBJECT"),
			Email:   value("BOOTSTRAP_EMAIL"),
		},
	}
	ttl, err := time.ParseDuration(envDefault("SESSION_TTL", "12h"))
	if err != nil {
		return Config{}, fmt.Errorf("SESSION_TTL: %w", err)
	}
	cfg.SessionTTL = ttl
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if _, err := time.LoadLocation(cfg.TimeZone); err != nil {
		return Config{}, fmt.Errorf("ALERT_TIMEZONE: %w", err)
	}
	if cfg.OIDC.RedirectURL == "" {
		cfg.OIDC.RedirectURL = cfg.PublicURL + "/api/v1/auth/callback"
	}
	return cfg, nil
}

func value(key string) string {
	if file := os.Getenv(key + "_FILE"); file != "" {
		body, err := os.ReadFile(file)
		if err == nil {
			return strings.TrimSpace(string(body))
		}
	}
	return strings.TrimSpace(os.Getenv(key))
}

func envDefault(key, fallback string) string {
	if v := value(key); v != "" {
		return v
	}
	return fallback
}

func split(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// BoolFrom is a small helper for tests and flags.
func BoolFrom(raw string) bool {
	value, err := strconv.ParseBool(raw)
	return err == nil && value
}
