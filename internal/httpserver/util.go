package httpserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const maxBody = 1 << 20

type httpError struct {
	status int
	code   string
}

func (e httpError) Error() string { return e.code }

func errStatus(status int, code string) error { return httpError{status: status, code: code} }

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

func (s *Server) fail(w http.ResponseWriter, status int, code string) {
	s.writeJSON(w, status, map[string]string{"error": code})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Header.Get("X-Requested-With") != "fetch" {
		s.fail(w, http.StatusForbidden, "csrf")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		s.fail(w, http.StatusBadRequest, "bad_json")
		return false
	}
	return true
}

func (s *Server) sendError(w http.ResponseWriter, err error) {
	var httpErr httpError
	if errors.As(err, &httpErr) {
		s.fail(w, httpErr.status, httpErr.code)
		return
	}
	if isNoRows(err) {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if isUnique(err) {
		s.fail(w, http.StatusConflict, "conflict")
		return
	}
	s.fail(w, http.StatusInternalServerError, "server")
}

func pathID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		return uuid.Nil, errStatus(http.StatusBadRequest, "bad_id")
	}
	return id, nil
}

func newSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func decodeB64(value string, exact, min, max int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
	}
	if exact > 0 && len(raw) != exact {
		return nil, errors.New("length")
	}
	if min > 0 && len(raw) < min {
		return nil, errors.New("length")
	}
	if max > 0 && len(raw) > max {
		return nil, errors.New("length")
	}
	return raw, nil
}

func encodeB64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !s.Cfg.TrustProxy {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}
	return strings.TrimSpace(strings.Split(forwarded, ",")[0])
}

func clip(value string, max int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > max {
		return string(runes[:max])
	}
	return value
}

func httpURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		return raw
	}
	return ""
}

func hexColor(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) != 7 || raw[0] != '#' {
		return fallback
	}
	for _, r := range raw[1:] {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return fallback
		}
	}
	return strings.ToLower(raw)
}

func logoFrom(name, logo string) string {
	logo = clip(logo, 3)
	if logo != "" {
		return logo
	}
	runes := []rune(strings.ToUpper(name))
	if len(runes) > 2 {
		runes = runes[:2]
	}
	if len(runes) == 0 {
		return "?"
	}
	return string(runes)
}
