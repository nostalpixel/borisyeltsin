# BorisEltsyn implementation plan

Agent contract for this repository. Spec lives in `requirements/INITIAL_REQUIREMENTS.md` (gitignored local copy). Ship a working modular monolith. Do not widen the stack.

## Done means

A clean `docker compose up -d` runs Postgres and one container. That container serves the React app and the JSON API. Uninvited people cannot get a session. Vault fields are ciphertext. Tests cover authorization, invitations, and client cryptography. Docs state the threat model without extra claims.

## Stack lock

- Web: React, TypeScript, Vite, Tailwind. Client crypto: `libsodium-wrappers-sumo` only. The non-sumo npm build omits `crypto_pwhash`.
- API: Go, chi, pgx, sqlc. One process serves API, embedded UI, and the renewal scheduler.
- Data: PostgreSQL. Migrations in `db/migrations`. Queries in `db/queries`. Generated code in `internal/db`.
- Identity: external Authentik. Authorization Code + PKCE. Server session cookie. No local passwords.
- Deploy: multi-stage Dockerfile, non-root, Compose. No Redis, Kubernetes, message bus, or second app runtime.

## Crypto lock (do not redesign)

Established libsodium constructions. No new cipher, KDF, or key exchange.

| Use | Construction |
|---|---|
| Identity key | `crypto_box_keypair` (X25519) |
| Passphrase KEK | `crypto_pwhash` Argon2id, opslimit 3, memlimit 64 MiB, 16-byte salt, 32-byte output |
| Private-key backup | `crypto_secretbox_easy` under the KEK |
| Recovery backup | second `crypto_secretbox_easy` under a 32-byte random recovery key shown once |
| Vault payload | `crypto_aead_xchacha20poly1305_ietf` with AAD `v1\|<vault_id>\|<item_id>\|<key_version>` |
| Member envelope | `crypto_box_seal` of `{v, vault_id, key_version, key}` |
| Org recovery | 2-of-2 XOR split of a 32-byte recovery key. Each share is `crypto_box_seal`ed to one custodian. Vault keys are `secretbox`ed under the combined key |

XChaCha20-Poly1305 is the reviewed AEAD because libsodium AES-GCM is not portable in browsers. Sealed boxes have no AAD, so the vault id and key version sit inside the plaintext and the client rejects mismatches.

The server stores public keys, fingerprints (SHA-256 of the raw public key, computed server-side), KDF parameters, nonces, and ciphertext. It never receives passphrases, private keys, recovery keys, or unwrapped vault keys.

Key distribution runs in a browser that already holds the vault key. An application admin who is not a vault member cannot mint envelopes. The first bootstrap admin may approve only their own key, and only while they are the sole user. Every later key needs a different active admin.

Server rejects KDF parameters below the production floor.

## Order of work

Check a box only after tests for that slice pass.

1. [x] Gitignore entries for Go, Node, Vite, secrets, and local data.
2. [x] Schema, sqlc, migrator, config, health endpoints.
3. [x] Sessions, OIDC PKCE, MFA `amr` fail-closed, CSRF, security headers.
4. [x] Invitations: 32-byte token, SHA-256 at rest, 24h expiry, single use, revoke, issuer+subject match, identical client error.
5. [x] Users, roles, service grants, audit log with a secret-field denylist.
6. [x] Services, accounts, subscriptions, payment methods (nickname, issuer, last4, expiry only), payments, dashboard, 7/3/1 renewal alerts.
7. [x] CSV and SpreadsheetML export. JSON import of the documented non-secret shape.
8. [x] Crypto document, then identity enrollment, fingerprint approval, vaults, envelopes, items, rotation, offboarding flags, 2-custodian recovery.
9. [x] React UI for those flows. Unlock and encrypt in the browser.
10. [x] Dockerfile, Compose, `.env.example`, GitHub Actions, README, threat model, recovery runbook.

## Request rules

- Session cookie: `be_session`, HttpOnly, Secure by default, SameSite=Lax.
- Mutating `/api/v1/*` requires `X-CSRF-Token` equal to the session secret.
- Object access is scoped by `organization_id` from the session. Missing and forbidden objects both return 404.
- Invitation token travels in an HttpOnly cookie set from the hash fragment, never in a query string.
- Body limit 1 MiB. Rate-limit login starts, invite accepts, and enrollment per process.

## Role rules

| App role | Services | Vault keys |
|---|---|---|
| admin | all metadata | none unless a vault member |
| manager | owner or granted | none unless a vault member |
| member | view owner or granted | none unless a vault member |
| readonly | view owner or granted | none unless a vault member |

| Vault role | Can |
|---|---|
| owner | read, write, members, envelopes, rotate |
| manager | read, write |
| member | read |

Revoked users lose sessions immediately. Removing a member deletes their envelopes. Rotation replaces item ciphertext and writes envelopes only for current members. Old rows are deleted in the same transaction. Interrupted rotation leaves the previous `key_version` in place.

## Layout

```
cmd/boriseltsyn/main.go
db/migrations/001_init.sql
db/queries/queries.sql
internal/db/                 sqlc output
internal/config/
internal/migrate/
internal/authz/
internal/token/
internal/spend/
internal/importer/
internal/scheduler/
internal/httpserver/
internal/testpg/
web/src/crypto/vault.ts
web/src/pages/
docs/CRYPTO.md
docs/THREAT_MODEL.md
docs/RECOVERY.md
```

## Verify

```
go test ./...
cd web && npm test && npm run build
docker compose config
```

Integration tests start Postgres with Docker and skip when Docker is unavailable. Do not stub authorization to make a test pass.

## Bootstrap

When the database has zero organizations and the bootstrap env vars are set, startup creates the org and prints one invite token to stdout (`BOOTSTRAP_INVITE_TOKEN=`). The token is not logged again. There is no public registration.

## Reference app

`Сервисы.html` (local, not committed) is the visual and import reference. Match its workspace: left category nav, metric row, search, filters, expandable service cards, inline account edits, due colors.

Backup JSON is `{version:1, services:[{name,url,category,description,unclear,logo,bg,fg,accounts:[{label,login,password,cost,currency,date,card,notes}]}]}`.

Categories: `infra`, `domains`, `tools`, `comms`, `partners`, `payments`, `other`. Currencies include `USDT`. Due paint: 4–7 days warning, 3 or fewer and overdue danger.

Import path: the browser strips `password`, encrypts it into a vault item, and posts only non-secret fields. The API rejects bodies that still contain `password`, `secret`, `cvv`, or a 13–19 digit card number. Excel and CSV exports omit secrets. The old workbook included them; this one does not.

Account cost in the reference is a monthly amount. Import creates a monthly subscription on that account. The editor also offers quarterly, annual, and custom cycles.

## Deliberate non-goals

- Email delivery. Alerts are stored and shown in the app.
- A Kubernetes chart, Redis, or a separate frontend container.
- Recovering a vault when every share and recovery key is gone.
- Claiming the server can prove a browser did not copy plaintext.
