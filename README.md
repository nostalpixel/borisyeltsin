![BorisYeltsin](docs/main_banner.png)

# BorisYeltsin

Subscription ledger and team credential vault for a small organization. One Go process serves the API, the renewal scheduler, and the compiled React application. Postgres stores the ledger in the clear and the vault as ciphertext. People sign in with an external Authentik. There is no local password and no public registration.

Repository: [github.com/nostalpixel/borisyeltsin](https://github.com/nostalpixel/borisyeltsin). License: MIT.

## Run

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD and the OIDC variables. See below.
docker compose up -d
```

`docker compose up` fails until `POSTGRES_PASSWORD` is set. Compose starts `postgres` (no published port) and `boriseltsyn` on port 8080. The image build runs the web build, then a static Go binary, and runs as uid 10001. Migrations run on startup.

`/healthz` reports that the process is listening. `/readyz` pings Postgres. The image health check uses `/readyz`.

The database URL inside Compose uses `sslmode=disable` on the Docker network. Put TLS on the reverse proxy in front of port 8080. `COOKIE_SECURE` defaults to `true`, so the session cookie only travels over HTTPS. Set it to `false` only to try the app over plain `http://localhost`. Leave `TRUST_PROXY` false unless that proxy sets `X-Forwarded-For` and you want it used as the rate-limit key.

### Release images

Tagged releases are published as `ghcr.io/nostalpixel/borisyeltsin` for `linux/amd64` and `linux/arm64`. Set `BORISELTSYN_VERSION` to a release version (for example `0.1.0`) and pull instead of building:

```bash
docker compose pull boriseltsyn
docker compose up -d --no-build
```

The default `BORISELTSYN_VERSION` is `dev`, which is never published, so a plain `docker compose up` builds the image from this checkout. Before upgrading to a release that contains a migration, take a `pg_dump` (see [docs/BACKUP.md](docs/BACKUP.md)).

Pushing a tag `vX.Y.Z` runs the whole CI and then publishes the image. The release fails without pushing if Trivy finds a fixable HIGH or CRITICAL vulnerability. CI also runs `npm audit` on shipped dependencies, starts the Compose stack, checks `/readyz` and the security headers, creates a bootstrap invite, and runs the restore drill. Dependabot opens weekly update PRs for Go, npm, Docker base images and Actions.

Secrets may be passed as `NAME_FILE` paths, for example `OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret`. A readable file replaces the plain environment variable. This includes `DATABASE_URL_FILE`.

### Authentik

Create a confidential OIDC client. Redirect URL: `${PUBLIC_URL}/api/v1/auth/callback`. Scopes: `openid`, `profile`, `email`. The authorization server must put an MFA method in the `amr` claim. The default allow-list is `mfa`, `otp`, `totp`, `webauthn`. A token without one of those values does not create a usable session.

Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET`. With an empty issuer the process still starts and login returns 503.

### First administrator

While the database has zero users, set all four bootstrap variables:

- `BOOTSTRAP_ORG_NAME`
- `BOOTSTRAP_OIDC_ISSUER` (same issuer the person will log in with)
- `BOOTSTRAP_OIDC_SUBJECT` (the Authentik subject)
- `BOOTSTRAP_EMAIL`

Then create the invite from the running container:

```bash
docker compose exec boriseltsyn boriseltsyn bootstrap-invite
```

It prints `BOOTSTRAP_INVITE_TOKEN=` to that terminal only; the server log never contains it. The database stores only a SHA-256 of the token. The token lasts 24 hours and works once. Running the command again revokes the earlier token and prints a new one. Once the first person has signed in, the command refuses to run.

Paste the token on the login page. The browser stores it in an HttpOnly cookie and sends the person to Authentik. After MFA, the browser generates an X25519 key, asks for a passphrase of at least 12 characters, and shows a personal recovery key once. The sole user may approve their own key. Every later key needs a different active admin.

Vault passwords cannot be saved until two members with approved keys become recovery custodians. The ledger works before that.

Read [docs/RECOVERY.md](docs/RECOVERY.md) before storing a real password. If the passphrase, the personal recovery key, and both organization shares are lost, the vault cannot be opened.

## Develop

```bash
go test ./...
cd web && npm test && npm run build
POSTGRES_PASSWORD=ci docker compose config
```

Integration tests start `postgres:16-alpine` and skip when Docker is missing. `make ui` copies a local Vite build into the embed directory for `go run`. Do not commit that copy. The image build copies the UI itself.

Generated sqlc code is committed. Regenerate with sqlc 1.30.0 and keep the diff empty.

## Documents

- [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) — agent work order
- [docs/CRYPTO.md](docs/CRYPTO.md) — constructions, additional data, and what the server cannot prove
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — mitigations and the claims this project does not make
- [docs/RECOVERY.md](docs/RECOVERY.md) — personal key, two custodians, departure, and permanent loss
- [docs/BACKUP.md](docs/BACKUP.md) — `pg_dump` and the secret-free export
- [SECURITY.md](SECURITY.md) — reporting and the short limit list
- [DESIGN.md](DESIGN.md) — theme tokens, type, retro budget, layout and accessibility rules

## Stack

React, TypeScript, Vite, Tailwind. Client crypto: `libsodium-wrappers-sumo`. Go, chi, pgx, sqlc. PostgreSQL 16. Authentik OIDC with PKCE. Docker Compose. No Redis, Kubernetes, or second application process.
