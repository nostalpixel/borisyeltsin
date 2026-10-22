package httpserver

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/nostalpixel/borisyeltsin/internal/db"
)

// Account documents (docs/CRYPTO.md "Account documents"). The browser checks
// the format and encrypts each file with its own key before upload, so the
// server sees only the size. It enforces size, count and vault quota, and the
// same access rules as the account the file belongs to.
const (
	// MaxFileBytes is the largest document, before encryption.
	MaxFileBytes = 10 << 20
	// fileOverhead is the XChaCha20-Poly1305 nonce and tag around each file.
	fileOverhead     = 24 + 16
	maxFilesAccount  = 20
	maxVaultBytes    = 1 << 30
	octetStream      = "application/octet-stream"
	fileAuditAccount = "account_id"
)

// fileAccount loads the account a file belongs to and applies the service
// rules: viewing it needs view access, changing it needs edit access.
func (s *Server) fileAccount(ctx context.Context, p Principal, accountID, vaultID uuid.UUID, edit bool) error {
	account, err := s.Q.GetAccount(ctx, db.GetAccountParams{ID: accountID, OrganizationID: p.OrgID})
	if err != nil {
		return errStatus(http.StatusNotFound, "not_found")
	}
	if _, err := s.serviceFor(ctx, p, account.ServiceID, edit); err != nil {
		return err
	}
	// An account's password and files live in one vault.
	if account.VaultID != nil && *account.VaultID != vaultID {
		return errStatus(http.StatusBadRequest, "bad_file")
	}
	return nil
}

func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	fileID, err1 := uuid.Parse(r.URL.Query().Get("id"))
	accountID, err2 := uuid.Parse(r.URL.Query().Get("account"))
	if err1 != nil || err2 != nil || fileID == uuid.Nil {
		s.fail(w, http.StatusBadRequest, "bad_file")
		return
	}
	if media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); media != octetStream {
		s.fail(w, http.StatusUnsupportedMediaType, "bad_file")
		return
	}
	if err := s.fileAccount(r.Context(), p, accountID, vaultID, true); err != nil {
		s.sendError(w, err)
		return
	}
	// Turn away non-members before reading up to 10 MiB; the check repeats
	// under the vault lock below.
	vault, err := s.Q.GetVault(r.Context(), db.GetVaultParams{ID: vaultID, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if err := requireItemAccess(r.Context(), s.Q, p, vault, true); err != nil {
		s.sendError(w, err)
		return
	}
	content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxFileBytes+fileOverhead))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		s.fail(w, http.StatusRequestEntityTooLarge, "file_too_large")
		return
	}
	if err != nil || len(content) <= fileOverhead {
		s.fail(w, http.StatusBadRequest, "bad_file")
		return
	}
	err = s.withVaultLock(r.Context(), p.OrgID, vaultID, func(q *db.Queries, vault db.Vault) error {
		if err := requireItemAccess(r.Context(), q, p, vault, true); err != nil {
			return err
		}
		ready, err := recoveryReady(r.Context(), q, p.OrgID)
		if err != nil {
			return err
		}
		if ready == nil {
			return errStatus(http.StatusConflict, "recovery_not_ready")
		}
		count, err := q.CountAccountFiles(r.Context(), accountID)
		if err != nil {
			return err
		}
		if count >= maxFilesAccount {
			return errStatus(http.StatusConflict, "too_many_files")
		}
		used, err := q.VaultFileBytes(r.Context(), vaultID)
		if err != nil {
			return err
		}
		if used+int64(len(content)) > maxVaultBytes {
			return errStatus(http.StatusInsufficientStorage, "storage_full")
		}
		if _, err := q.InsertVaultFile(r.Context(), db.InsertVaultFileParams{
			ID: fileID, VaultID: vaultID, AccountID: accountID, Size: int64(len(content)), Content: content, CreatedBy: p.UserID,
		}); isUnique(err) {
			return errStatus(http.StatusConflict, "bad_file")
		} else if err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "vault_file_added", "vault_file", fileID.String(),
			map[string]string{fileAuditAccount: accountID.String(), "bytes": strconv.Itoa(len(content))})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"id": fileID, "size": len(content)})
}

// fileFor checks access to a stored file and returns its metadata.
func (s *Server) fileFor(r *http.Request, p Principal, write bool) (db.GetVaultFileMetaRow, error) {
	vaultID, err := pathID(r, "vaultID")
	if err != nil {
		return db.GetVaultFileMetaRow{}, err
	}
	fileID, err := pathID(r, "fileID")
	if err != nil {
		return db.GetVaultFileMetaRow{}, err
	}
	vault, err := s.Q.GetVault(r.Context(), db.GetVaultParams{ID: vaultID, OrganizationID: p.OrgID})
	if err != nil {
		return db.GetVaultFileMetaRow{}, errStatus(http.StatusNotFound, "not_found")
	}
	if err := requireItemAccess(r.Context(), s.Q, p, vault, write); err != nil {
		return db.GetVaultFileMetaRow{}, err
	}
	meta, err := s.Q.GetVaultFileMeta(r.Context(), db.GetVaultFileMetaParams{ID: fileID, VaultID: vaultID})
	if err != nil {
		return db.GetVaultFileMetaRow{}, errStatus(http.StatusNotFound, "not_found")
	}
	if err := s.fileAccount(r.Context(), p, meta.AccountID, vaultID, write); err != nil {
		return db.GetVaultFileMetaRow{}, err
	}
	return meta, nil
}

func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	meta, err := s.fileFor(r, p, false)
	if err != nil {
		s.sendError(w, err)
		return
	}
	content, err := s.Q.GetVaultFileContent(r.Context(), db.GetVaultFileContentParams{ID: meta.ID, VaultID: meta.VaultID})
	if err != nil {
		s.sendError(w, err)
		return
	}
	w.Header().Set("Content-Type", octetStream)
	w.Header().Set("Content-Disposition", "attachment")
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	meta, err := s.fileFor(r, p, true)
	if err != nil {
		s.sendError(w, err)
		return
	}
	err = s.withVaultLock(r.Context(), p.OrgID, meta.VaultID, func(q *db.Queries, _ db.Vault) error {
		if _, err := q.DeleteVaultFile(r.Context(), db.DeleteVaultFileParams{ID: meta.ID, VaultID: meta.VaultID}); err != nil {
			return err
		}
		return auditTx(r.Context(), q, p.OrgID, &p.UserID, "vault_file_deleted", "vault_file", meta.ID.String(),
			map[string]string{fileAuditAccount: meta.AccountID.String()})
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
