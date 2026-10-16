# TODOS

Deferred by /plan-ceo-review on 2026-10-17 (go-live core, SCOPE REDUCTION).

## Ledger UI completeness (D3.3)

Spec §3. API exists; UI missing: payment history (`/payments`), payment-method records (nickname/issuer/last4/expiry), auto-renew toggle, dashboard spend and overdue, unarchive and archived list, owner/tags/notes fields.
Known bug riding along: auto-renew subscriptions never advance their renewal date, so they show overdue forever. Alerts match exact days only (missed if the process is down) and are never pruned.
Why deferred: wave 1 is vault safety; the ledger already matches the reference HTML app.

## Audit completeness (D3.4)

Spec §10. Missing events: invitation expired, failed OIDC callback (`auth.go` deny path), MFA assurance failures (`auth.go`, `server.go` per-request check), secret/envelope/share reads, subscription update, payment-method delete.
Also: audit writes go through the pool, not the transaction (`auth.go` invite accept), so they can record events whose commit failed. Audit UI shows no actor.
Why deferred: Authentik already logs auth failures; small trusted team.

## Multi-vault routing (D15)

Wave 1 runs one org vault. Spec §6 example (Infrastructure Vault) implies several. Needs a vault picker, saves routed by `account.vault_id` (today `App.tsx` uses whichever vault is open), per-vault unlock.
Why deferred: one vault covers 5–25 people; removes a wrong-vault bug class from wave 1.

## Additional interface languages

Base UI is English (wave 1, C9). Add an i18n layer and other languages only after development settles.

## YubiKey vault unlock via WebAuthn PRF

**What:** Let a user unlock the vault with a YubiKey (or other FIDO2 key with PRF/hmac-secret) in addition to the passphrase.
**Why:** Stronger, faster unlock than typing a long passphrase; a stolen encrypted backup is useless without the physical key.
**Design sketch:** WebAuthn PRF output (32 bytes, per credential, per RP ID) -> HKDF -> key for a third `crypto_secretbox_easy` of the same X25519 private key, stored next to the passphrase and recovery backups. Passphrase stays as fallback. Each key enrolled separately; removing one deletes its backup row.
**Cons / risks:** Bound to the site's RP ID, so a domain change breaks it. Browser support for PRF varies (good in Chromium; check Safari/Firefox versions in use). Adds a wrapping path, so it is a crypto-lock change: document in docs/CRYPTO.md and include in the independent review (same review as the PR3 recovery redesign). Does not help against malware on an unlocked device.
**Context:** Login MFA with YubiKey already works through Authentik WebAuthn, as long as Authentik emits an `amr` value in the allow-list (`internal/authz/authz.go:108`). Verify that against a live Authentik flow.
**Effort:** human M / CC S. **Priority:** P2. **Depends on:** C2 pin store, CRYPTO.md review.
