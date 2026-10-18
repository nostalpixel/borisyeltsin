package httpserver

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/token"
)

// Agent tokens (docs/MCP.md) let an MCP client read the ledger, and with
// can_write add subscriptions, as the person who created the token.

const (
	apiTokenPrefix   = "bey_"
	maxAPITokens     = 10
	maxAPITokenDays  = 90
	defaultTokenDays = 30
)

type tokenBody struct {
	Name     string `json:"name"`
	CanWrite bool   `json:"can_write"`
	Days     int    `json:"days"`
}

func tokenView(id uuid.UUID, name string, canWrite bool, created, expires time.Time, used, revoked pgtype.Timestamptz) map[string]any {
	var lastUsed *time.Time
	if used.Valid {
		lastUsed = &used.Time
	}
	return map[string]any{
		"id": id, "name": name, "can_write": canWrite,
		"created_at": created, "expires_at": expires, "last_used_at": lastUsed, "revoked": revoked.Valid,
	}
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	all := p.Role == "admin" && r.URL.Query().Get("all") == "1"
	rows, err := s.Q.ListAPITokens(r.Context(), db.ListAPITokensParams{OrganizationID: p.OrgID, AllUsers: all, UserID: p.UserID})
	if err != nil {
		s.sendError(w, err)
		return
	}
	out := []map[string]any{}
	for _, row := range rows {
		view := tokenView(row.ID, row.Name, row.CanWrite, row.CreatedAt, row.ExpiresAt, row.LastUsedAt, row.RevokedAt)
		view["owner"] = map[string]any{"id": row.UserID, "display_name": row.DisplayName, "email": row.Email}
		view["mine"] = row.UserID == p.UserID
		out = append(out, view)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if !s.Limit.Allow("token:" + p.UserID.String()) {
		s.fail(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var body tokenBody
	if !s.decode(w, r, &body) {
		return
	}
	body.Name = clip(body.Name, 80)
	if body.Name == "" {
		s.fail(w, http.StatusBadRequest, "bad_token")
		return
	}
	if body.Days == 0 {
		body.Days = defaultTokenDays
	}
	if body.Days < 1 || body.Days > maxAPITokenDays {
		s.fail(w, http.StatusBadRequest, "bad_token")
		return
	}
	if body.CanWrite && p.Role == "readonly" {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	live, err := s.Q.CountLiveAPITokens(r.Context(), p.UserID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if live >= maxAPITokens {
		s.fail(w, http.StatusConflict, "too_many_tokens")
		return
	}
	secret, _, err := token.New()
	if err != nil {
		s.sendError(w, err)
		return
	}
	plain := apiTokenPrefix + secret
	row, err := s.Q.CreateAPIToken(r.Context(), db.CreateAPITokenParams{
		OrganizationID: p.OrgID, UserID: p.UserID, Name: body.Name, TokenHash: token.Hash(plain),
		CanWrite: body.CanWrite, ExpiresAt: s.now().Add(time.Duration(body.Days) * 24 * time.Hour),
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	access := "read"
	if row.CanWrite {
		access = "read_write"
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "api_token_created", "api_token", row.ID.String(), map[string]string{"access": access})
	view := tokenView(row.ID, row.Name, row.CanWrite, row.CreatedAt, row.ExpiresAt, row.LastUsedAt, row.RevokedAt)
	// The plaintext is shown once; the server keeps only its SHA-256.
	view["token"] = plain
	s.writeJSON(w, http.StatusCreated, view)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	id, err := pathID(r, "tokenID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	row, err := s.Q.RevokeAPIToken(r.Context(), db.RevokeAPITokenParams{ID: id, OrganizationID: p.OrgID, AnyUser: p.Role == "admin", UserID: p.UserID})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "api_token_revoked", "api_token", row.ID.String(), map[string]string{"owner": row.UserID.String()})
	s.writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// withAPIToken authenticates a bearer agent token. Browsers never send it on
// their own, so the MCP route needs no CSRF check.
func (s *Server) withAPIToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deny := func() {
			w.Header().Set("WWW-Authenticate", `Bearer realm="borisyeltsin"`)
			s.fail(w, http.StatusUnauthorized, "auth_required")
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !strings.HasPrefix(raw, apiTokenPrefix) || len(raw) > 128 {
			deny()
			return
		}
		row, err := s.Q.GetActiveAPIToken(r.Context(), token.Hash(raw))
		if err != nil {
			if !s.Limit.Allow("mcp-fail:" + s.clientIP(r)) {
				s.fail(w, http.StatusTooManyRequests, "rate_limited")
				return
			}
			deny()
			return
		}
		if !s.MCPLimit.Allow("mcp:" + row.ID.String()) {
			s.fail(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		_ = s.Q.TouchAPIToken(r.Context(), row.ID)
		p := Principal{
			UserID: row.UserID, OrgID: row.OrganizationID, Email: row.Email,
			Name: row.DisplayName, Role: row.Role, Status: row.Status,
		}
		ctx := withAgent(r.Context(), p, agentToken{ID: row.ID, CanWrite: row.CanWrite && row.Role != "readonly"})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
