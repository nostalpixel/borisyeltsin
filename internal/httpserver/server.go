package httpserver

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nostalpixel/borisyeltsin/internal/authz"
	"github.com/nostalpixel/borisyeltsin/internal/config"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/fieldsafe"
	"github.com/nostalpixel/borisyeltsin/internal/limiter"
	"github.com/nostalpixel/borisyeltsin/internal/token"
)

//go:embed all:dist
var uiFiles embed.FS

// Principal is the authenticated caller. Values come from the server session.
type Principal struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
	OrgID     uuid.UUID
	Email     string
	Name      string
	Role      string
	Status    string
	CSRF      string
	AMR       []string
	Issuer    string
	Subject   string
}

type ctxKey int

const principalKey ctxKey = 1

// Server is the HTTP API and embedded UI.
type Server struct {
	Pool  *pgxpool.Pool
	Q     *db.Queries
	Cfg   config.Config
	Loc   *time.Location
	Limit *limiter.Limiter
	OIDC  *oidcClient
	Now   func() time.Time
}

func New(pool *pgxpool.Pool, cfg config.Config) *Server {
	loc, err := time.LoadLocation(cfg.TimeZone)
	if err != nil || cfg.TimeZone == "" {
		loc = time.UTC
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if len(cfg.MFAAMR) == 0 {
		cfg.MFAAMR = []string{"mfa", "otp", "totp", "webauthn"}
	}
	return &Server{
		Pool:  pool,
		Q:     db.New(pool),
		Cfg:   cfg,
		Loc:   loc,
		Limit: limiter.New(30, time.Minute),
		Now:   time.Now,
	}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(s.securityHeaders)
	r.Get("/healthz", s.health)
	r.Get("/readyz", s.ready)
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/auth/login", s.login)
		r.Get("/auth/callback", s.callback)
		r.Post("/auth/invite", s.stashInvite)
		r.Group(func(r chi.Router) {
			r.Use(s.withSession)
			r.Use(s.withCSRF)
			r.Get("/session", s.getSession)
			r.Post("/session/logout", s.logout)
			r.Post("/crypto/identity", s.enroll)
			r.Get("/crypto/me", s.myIdentity)
			// The sole bootstrap admin is pending_approval until this call succeeds.
			// CanApproveKey rejects every other non-active caller.
			r.Post("/crypto/users/{userID}/approve", s.approveKey)
			r.Post("/crypto/users/{userID}/reject", s.rejectKey)
			r.Group(func(r chi.Router) {
				r.Use(s.requireActive)
				r.Get("/workspace", s.workspace)
				r.Post("/services", s.createService)
				r.Patch("/services/{serviceID}", s.updateService)
				r.Post("/services/{serviceID}/archive", s.archiveService)
				r.Post("/services/{serviceID}/grants", s.grantService)
				r.Delete("/services/{serviceID}/grants/{userID}", s.revokeGrant)
				r.Post("/services/{serviceID}/accounts", s.createAccount)
				r.Patch("/accounts/{accountID}", s.updateAccount)
				r.Delete("/accounts/{accountID}", s.deleteAccount)
				r.Post("/accounts/{accountID}/vault-link", s.linkVaultItem)
				r.Post("/subscriptions", s.createSubscription)
				r.Patch("/subscriptions/{subscriptionID}", s.updateSubscription)
				r.Post("/subscriptions/{subscriptionID}/payments", s.addPayment)
				r.Get("/subscriptions/{subscriptionID}/payments", s.listPayments)
				r.Get("/payment-methods", s.listPaymentMethods)
				r.Post("/payment-methods", s.createPaymentMethod)
				r.Delete("/payment-methods/{methodID}", s.deletePaymentMethod)
				r.Post("/imports/services", s.importServices)
				r.Get("/exports/services.csv", s.exportCSV)
				r.Get("/exports/services.xlsx", s.exportXLSX)
				r.Get("/users", s.listUsers)
				r.Post("/users/{userID}/role", s.changeRole)
				r.Post("/users/{userID}/revoke", s.revokeUser)
				r.Get("/invitations", s.listInvitations)
				r.Post("/invitations", s.createInvitation)
				r.Post("/invitations/{invitationID}/revoke", s.revokeInvitation)
				r.Get("/crypto/keys", s.listKeys)
				r.Get("/crypto/proposals", s.listProposals)
				r.Put("/crypto/identity/passphrase", s.changePassphrase)
				r.Get("/audit", s.listAudit)
				r.Get("/flags", s.listFlags)
				r.Post("/flags/{flagID}/resolve", s.resolveFlag)
				r.Get("/vaults", s.listVaults)
				r.Post("/vaults", s.createVault)
				r.Get("/vaults/{vaultID}", s.getVault)
				r.Post("/vaults/{vaultID}/members", s.addVaultMember)
				r.Delete("/vaults/{vaultID}/members/{userID}", s.removeVaultMember)
				r.Post("/vaults/{vaultID}/envelopes", s.putEnvelope)
				r.Get("/vaults/{vaultID}/envelope", s.getEnvelope)
				r.Get("/vaults/{vaultID}/items", s.listItems)
				r.Post("/vaults/{vaultID}/items", s.createItem)
				r.Put("/vaults/{vaultID}/items/{itemID}", s.updateItem)
				r.Delete("/vaults/{vaultID}/items/{itemID}", s.deleteItem)
				r.Post("/vaults/{vaultID}/rotation", s.rotateVault)
				r.Post("/vaults/{vaultID}/recovery-envelope", s.putRecoveryEnvelope)
				r.Get("/vaults/{vaultID}/recovery-envelope", s.getRecoveryEnvelope)
				r.Get("/recovery", s.getRecovery)
				r.Post("/recovery", s.putRecovery)
				r.Get("/recovery/share", s.getRecoveryShare)
			})
		})
	})
	ui, err := fs.Sub(uiFiles, "dist")
	if err == nil {
		r.NotFound(s.spa(ui))
	}
	return r
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// style-src-attr allows per-service logo colors. Inline style sheets stay blocked.
		// 'wasm-unsafe-eval' lets libsodium compile its WebAssembly build; without it the
		// asm.js fallback cannot run Argon2id at 64 MiB and key creation fails. It does not
		// allow eval() or inline scripts.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) spa(ui fs.FS) http.HandlerFunc {
	files := http.FileServer(http.FS(ui))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(ui, name); err != nil {
			r.URL.Path = "/"
			files.ServeHTTP(w, r)
			return
		}
		files.ServeHTTP(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.Pool.Ping(r.Context()); err != nil {
		s.fail(w, http.StatusServiceUnavailable, "not_ready")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func principalFrom(r *http.Request) (Principal, bool) {
	p, ok := r.Context().Value(principalKey).(Principal)
	return p, ok
}

func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("be_session")
		if err != nil {
			s.fail(w, http.StatusUnauthorized, "auth_required")
			return
		}
		if len(cookie.Value) < 32 || len(cookie.Value) > 128 {
			s.fail(w, http.StatusUnauthorized, "auth_required")
			return
		}
		row, err := s.Q.GetActiveSession(r.Context(), token.Hash(cookie.Value))
		if err != nil {
			s.fail(w, http.StatusUnauthorized, "auth_required")
			return
		}
		if !authz.MFASatisfied(row.Amr, s.Cfg.MFAAMR) {
			s.fail(w, http.StatusForbidden, "mfa_required")
			return
		}
		p := Principal{
			SessionID: row.ID,
			UserID:    row.UserID,
			OrgID:     row.OrganizationID,
			Email:     row.Email,
			Name:      row.DisplayName,
			Role:      row.Role,
			Status:    row.Status,
			CSRF:      row.CsrfSecret,
			AMR:       row.Amr,
			Issuer:    row.Issuer,
			Subject:   row.Subject,
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

func (s *Server) withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Requested-With") != "fetch" {
			s.fail(w, http.StatusForbidden, "csrf")
			return
		}
		p, ok := principalFrom(r)
		if !ok || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(p.CSRF)) != 1 {
			s.fail(w, http.StatusForbidden, "csrf")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireActive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFrom(r)
		if p.Status != "active" {
			s.fail(w, http.StatusForbidden, "approval_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAdmin(p Principal) error {
	if p.Role != "admin" || p.Status != "active" {
		return errStatus(http.StatusForbidden, "forbidden")
	}
	return nil
}

// audit records an event outside any transaction. Writes that must not be
// recorded unless they commit use auditTx with the transaction's queries.
func (s *Server) audit(ctx context.Context, org uuid.UUID, actor *uuid.UUID, action, targetType, targetID string, meta map[string]string) {
	_ = auditTx(ctx, s.Q, org, actor, action, targetType, targetID, meta)
}

func auditTx(ctx context.Context, q *db.Queries, org uuid.UUID, actor *uuid.UUID, action, targetType, targetID string, meta map[string]string) error {
	raw := []byte(`{}`)
	if len(meta) > 0 {
		encoded, err := json.Marshal(meta)
		if err == nil {
			raw = encoded
		}
	}
	if err := fieldsafe.RejectSecrets(raw); err != nil {
		raw = []byte(`{"redacted":true}`)
	}
	return q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		OrganizationID: org,
		ActorID:        actor,
		Action:         action,
		TargetType:     targetType,
		TargetID:       targetID,
		Metadata:       raw,
	})
}

func (s *Server) setCookie(w http.ResponseWriter, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.Cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
