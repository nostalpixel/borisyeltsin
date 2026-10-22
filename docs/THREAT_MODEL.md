# Threat model

This is the boundary of the vault, not a claim that the whole application is zero-knowledge. Subscription names, prices, dates, categories, membership, and audit rows are ordinary database fields. A person who can read Postgres can read them.

## Assets

- Account passwords, extra fields, attached documents and other vault payloads.
- Identity private keys and the passphrase that wraps them.
- Vault keys and the organization recovery key.
- Personal recovery keys and custodian shares.
- Session cookies and agent tokens.
- Subscription and payment metadata. Payment methods store a nickname, issuer, last4, and expiry. They do not store a full card number.

## Mitigations that exist in this repository

| Threat | What the code does |
|---|---|
| Stolen PostgreSQL backup | Vault payloads (including account documents and their file names), private keys, and recovery shares are ciphertext. Session cookies are stored as SHA-256 hashes, so a dump does not hand out live sessions. The backup still contains subscription metadata and public keys. |
| Compromised API process | The process has no vault key and no passphrase. It can serve malicious JavaScript. See the boundary below. |
| Malicious application admin | The admin role edits service metadata. It does not mint envelopes and cannot add itself to a vault. Adding members, sharing the key, and rotating require a vault owner who holds an envelope for the current key. Vault keys move only through client-side seals to approved public keys. |
| Stolen Authentik password | Login requires an `amr` value in the allow-list (`mfa`, `otp`, `totp`, `webauthn` by default). A session without that claim is rejected on every request. The vault passphrase is separate. |
| Stolen unlocked device | The private key is in page memory after unlock. Logout zeroes that buffer. A thief who copies the ciphertext still needs the passphrase or the personal recovery key. |
| Public-key substitution | A different active admin must approve a key, after comparing its fingerprint with the person out of band and typing its last group. The sole bootstrap user may approve only their own key, and only while they are the only user. The browser seals a vault key, a custodian share or a rotation envelope only to a key whose fingerprint someone verified in that browser; the verified fingerprint is pinned there, and a different key for the same person is blocked until it is verified again. The client refuses to open an identity whose fingerprint does not match the approved public key. |
| Invitation interception | Two random words from a 7,772-word list (about 26 bits), SHA-256 at rest, 24-hour expiry, single use, bound to the OIDC issuer and subject. The client error is the same for a bad token and a failed login. The short key is safe only because of the subject binding: a guessed key does nothing for anyone who cannot already sign in as the invited Authentik user. |
| XSS | CSP is `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`. `'wasm-unsafe-eval'` lets libsodium compile WebAssembly (Argon2id needs it); it does not allow `eval()`. `style-src-attr` exists so logo colors can be set on elements. Inline scripts and inline stylesheets stay blocked. |
| CSRF | Session cookie is HttpOnly, SameSite=Lax, and Secure unless `COOKIE_SECURE=false`. Mutating `/api/v1` calls need `X-Requested-With: fetch` and, once a session exists, `X-CSRF-Token`. |
| IDOR | Queries are scoped by the session organization. Missing and forbidden objects both return 404. |
| Offline passphrase guessing | Argon2id at opslimit 3 and 64 MiB. A weak passphrase still falls quickly. The server rate-limits login and enrollment per process. It cannot rate-limit an offline attack on a stolen backup. |
| Revoked member | Revocation drops sessions, memberships, and envelopes, and marks the vault for rotation. Secrets that person already copied are outside this system. |
| Lost keys | Personal recovery key, or both organization shares together. See `RECOVERY.md`. |
| Recovery key substitution or rollback | Shares are authenticated boxes from the setting-up admin's verified key and carry the recovery public key; custodians check it before confirming. Browsers pin the recovery key with its epoch and refuse an older epoch or a changed fingerprint. |
| Recovery by one person | The two custodians must be different users with different keys. Recovery needs both shares in one browser and a server challenge opened with the recombined key; challenges are single-use, expire in 5 minutes, and are limited to 5 per custodian per hour. |
| Departed custodian | Revoking a custodian, replacing a custodian's key, or revoking the admin who set up the recovery key degrades recovery: it is refused, new passwords are blocked, and the vault needs rotation until a new recovery key is set up. A used recovery key is spent and never reused. |
| Malicious document | Documents are checked in the browser before upload (open formats and PDF only, contents must match the extension) and are only ever downloaded, never rendered in the app's origin. A PDF or ODF file can still carry an exploit for the reader that opens it on the person's machine; the app does not scan files, because it cannot read them. |
| Stolen agent token | Agent tokens (`docs/MCP.md`) reach only `/mcp`, which reads the ledger and, for write tokens, adds subscriptions. They never reach the vault, keys, members or recovery. 32 random bytes, SHA-256 at rest, at most 90 days, revocable, revoked with their owner, and limited to what the owner can see and edit. A token skips Authentik MFA by design, so the risk is ledger disclosure and unwanted subscription rows until it is revoked. |

## Boundaries

The application does not protect against:

- Malware on an unlocked device, or a person looking at an unlocked screen.
- Malicious JavaScript delivered by a compromised application server or a compromised build of this repository. Browser encryption cannot detect that the page itself was replaced.
- Credentials a former member already copied.
- Full compromise of Authentik together with the vault passphrase, the personal recovery key, or both organization shares.
- The two recovery custodians acting together. That is the recovery procedure, not an unexpected break.
- A database administrator editing or deleting ordinary audit rows. The audit log is not an append-only transparency log.

The server also cannot prove that a browser displayed, copied, or did not copy a decrypted password. Audit rows record API actions such as item writes. They do not record a view that stayed inside the browser.

Lost passphrase recovery is the personal recovery key. An Authentik password reset is not that key.

If the passphrase, the personal recovery key, and both organization shares are all gone, the vault ciphertext in Postgres cannot be decrypted. There is no operator override.

## Deployment assumptions

TLS is terminated by a reverse proxy in front of this process. Compose publishes the application port and does not publish Postgres. The database URL inside Compose uses `sslmode=disable` on the Docker network. Do not put that URL on a public network.

`TRUST_PROXY` defaults to false. Turn it on only when a proxy you control sets `X-Forwarded-For`. It affects the rate-limit key, not authorization.

`COOKIE_SECURE` defaults to true in the process and in the Compose file. Set it to false only to try the app over plain `http://localhost`.
