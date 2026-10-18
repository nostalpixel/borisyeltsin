# Cryptographic design

BorisYeltsin uses libsodium constructions only. This document records the choices that are already in the client and the server checks around them. It is not a new protocol.

Do not put real organizational credentials in the vault until someone other than the implementer has reviewed this design.

**Review status.** The "Organization recovery" section describes recovery format 2, which is not implemented yet. It replaces format 1 (a symmetric key split between custodians), which needed both shares for every routine rotation. Format 2 is written down first so it can be reviewed before code lands. Everything else in this document describes code that ships today.

## Library

The browser uses `libsodium-wrappers-sumo` 0.7.15. The non-sumo package `libsodium-wrappers` ships a build that omits `crypto_pwhash`, so Argon2id is unavailable there. Types come from `@types/libsodium-wrappers`. The fingerprint is Web Crypto SHA-256 because the sumo TypeScript types do not expose `crypto_hash_sha256`.

The Go server does not decrypt vault payloads. It checks sizes, KDF floors, membership, and fingerprints. Fingerprints are `sha256.Sum256` of the raw 32-byte X25519 public key, hex-encoded. The browser digest must match that byte string.

Binary fields on the wire are standard base64 (`sodium.base64_variants.ORIGINAL`, Go `StdEncoding` with a raw-standard fallback). Invitation tokens are a separate encoding: base64 raw URL, and only the SHA-256 is stored.

## Constructions

| Use | Construction |
|---|---|
| Identity key | `crypto_box_keypair` (X25519) |
| Passphrase KEK | `crypto_pwhash` Argon2id, opslimit 3, memlimit 64 MiB (67108864), 16-byte salt, 32-byte output |
| Private-key backup | `crypto_secretbox_easy` under the KEK. Nonce is 24 bytes. |
| Personal recovery | A second `crypto_secretbox_easy` under a 32-byte random key. The key is shown once. It is not derived from the Authentik password. |
| Vault payload | `crypto_aead_xchacha20poly1305_ietf` |
| Member envelope | `crypto_box_seal` of a JSON payload |
| Organization recovery key | `crypto_box_keypair` (X25519), generated in an admin's browser. The private key is 2-of-2 XOR split and never stored whole. |
| Custodian share | `crypto_box_easy` (authenticated: sender is the setting-up admin's identity key, recipient is the custodian's identity key) of a JSON payload |
| Recovery envelope | `crypto_box_seal` of the member-envelope payload to the recovery public key |
| Recovery challenge | Server-side `crypto_box_seal` (Go `golang.org/x/crypto/nacl/box.SealAnonymous`) of 32 random bytes to the recovery public key |

XChaCha20-Poly1305 is the AEAD because libsodium AES-GCM is not portable in browsers. Sealed boxes have no additional data, so the vault id and key version sit inside the sealed plaintext and the client rejects a mismatch.

## Authenticated item data

Item additional data is the UTF-8 string:

```
v1|<vault_id>|<item_id>|<key_version>
```

`vault_id` and `item_id` are UUID strings. `key_version` is the decimal version used to encrypt that row. Changing any of the three makes `decrypt` fail.

Item plaintext is JSON `{"v":1,"password":"..."}`. The server stores the nonce and ciphertext. It does not see this JSON.

## Envelopes

A member envelope seals this JSON to the recipient public key:

```json
{"v":1,"vault_id":"<uuid>","key_version":1,"key":"<standard base64 of 32 bytes>"}
```

`openVaultKey` rejects a payload whose version, vault id, or key version does not match the vault the caller asked to open. The server stores `recipient_fingerprint`, the SHA-256 hex of the raw public key the client claimed. The server cannot open the box, so it cannot prove the ciphertext was actually sealed to that key. A member can upload garbage. That is a storage nuisance, not a decryption oracle.

The first envelope is accepted only when the vault has zero envelopes and the recipient is the caller. Later envelopes are written by a vault owner, or replaced as a set during rotation.

## Passphrase and personal recovery

Production KDF parameters are opslimit 3 and memlimit 67108864. The database `CHECK` rejects anything weaker, and the client refuses to unlock a record below that floor. Unlock uses the stored parameters when they meet the floor.

The passphrase is stretched in the browser and wiped with `memzero` after the secretbox is opened. The private key stays in page memory until logout, which `memzero`s it. Closing the vault view drops the React state. A copy can remain until garbage collection. Logout is the path that wipes the key.

The personal recovery key is 32 random bytes, standard-base64, shown once at enrollment. It opens the second secretbox. Resetting the Authentik password does not produce this key and does not open the vault.

## Organization recovery

Organization recovery lets two custodians together reopen the vault when nobody who holds an envelope can unlock it. It is separate from personal recovery and uses neither the Authentik password nor any member passphrase.

### Recovery key

An admin's browser generates an X25519 key pair, the recovery key. The public half is stored on the server with its fingerprint (SHA-256 of the raw 32 bytes, hex, as for identity keys). The private half is split and then wiped with `memzero`:

- `share1` is 32 random bytes.
- `share2` is `recovery_private_key XOR share1`.
- Either share alone is indistinguishable from random while the other stays secret.
- `share1 XOR share2` restores the private key, and `crypto_scalarmult_base` of it must equal the stored public key.

The server never sees the private key, a plaintext share or the combined value. Each setup is an **epoch** (an integer that increases by one per setup). Only one epoch is active at a time.

### Custodian shares

Each share is sent to its custodian with `crypto_box_easy`, from the setting-up admin's identity key to the custodian's approved identity key, with a fresh 24-byte nonce. The plaintext is:

```json
{"v":2,"org_id":"<uuid>","epoch":1,"share_index":1,"share":"<standard base64 of 32 bytes>","recovery_public_key":"<standard base64 of 32 bytes>"}
```

The box is authenticated, not sealed, so a custodian knows which colleague produced the share. The server cannot forge a share without an approved identity private key. `crypto_box` authenticates the pair, not one side: the custodian could also have produced the box. That is harmless here, because a custodian forging a share to themself gains nothing. An attacker who holds a custodian's identity private key can forge shares to that custodian, but that attacker can already open the real share. Before the admin's browser seals a share, both custodians' keys must be pinned (see "Verifying recipient keys").

A custodian **confirms** their share from their own browser:

1. Fetch the sealed share, the epoch's public key and the sender's public key.
2. Require the sender's key to be pinned, and open the box.
3. Check `v`, `org_id`, `epoch` and `share_index` against the request, and check that `recovery_public_key` equals the epoch's published key.
4. Pin the recovery key fingerprint for this organization, and post the fingerprint back.

The server accepts a confirmation only from that custodian, for that epoch, with the epoch's fingerprint. The epoch becomes active once **both** custodians have confirmed. Activation deletes older epochs and their recovery envelopes in the same transaction.

### Recovery envelopes and routine rotation

A recovery envelope is the member-envelope JSON (`{"v":1,"vault_id","key_version","key"}`) sealed with `crypto_box_seal` to the active recovery public key. The server stores it per `(vault_id, key_version)` together with the epoch it was sealed under.

Because sealing needs only the public key, routine rotation needs no custodian. The rotating owner's browser seals the new vault key to the recovery public key alongside the member envelopes. The browser refuses to seal to a recovery key that is not pinned with the published fingerprint. An unpinned key opens the verify dialog: compare the fingerprint with a custodian, who reads it from their confirmed share. A changed fingerprint is shown as a changed key and blocks sealing until it is verified again. An owner who unlocks after activation and finds no recovery envelope for the current key version seals one.

### Recovering

Recovery is used when nobody who holds an envelope can unlock, for example when the only owner lost both their passphrase and their personal recovery key. One custodian runs it in their own browser while the other reads them their share out of band:

1. The custodian opens their own share and enters the other custodian's share. The browser checks each 32-byte share, combines them, and derives the public key. A mismatch with the pinned recovery fingerprint fails with "shares do not match" and nothing is sent.
2. **Challenge.** The browser asks for a challenge. Only an active user who is a custodian of the active epoch may ask, including while the epoch is degraded (see below), because that is when recovery may be needed. At most 5 challenges per custodian per hour are issued. The server draws 32 random bytes, stores their SHA-256 with the custodian, the vault, the epoch and a 5-minute expiry, and returns `crypto_box_seal(challenge, recovery_public_key)`.
3. The browser opens the challenge with the recovered key pair and posts the 32 bytes back. The server compares hashes in constant time, marks the challenge used (one attempt per challenge), and creates a **recovery grant**: this custodian, this vault, 15 minutes. Both the challenge and the grant are audited, including failures.
4. With the grant, the browser reads the recovery envelope, the items (ciphertext) and the member list. It opens the vault key from the envelope and checks `vault_id` and `key_version`.
5. The browser rotates: new vault key, every live item re-encrypted, a recovery envelope sealed to the same recovery public key, and member envelopes for the members it keeps. The rotation must include an envelope for the recovering custodian. Inside the rotation transaction, the custodian becomes a vault owner. The grant is consumed.
6. The browser wipes the shares, the recovered private key and the old vault key with `memzero`, and clears the share fields.

The grant is the only exception to the owner gate in "Server-side write rules", and it covers only these reads and one rotation. An expired or used grant returns 403 and the custodian starts again at step 2. Possession of the recovery key, proven by the challenge, is the authority: an admin or custodian without both shares cannot get a grant.

Recovery does not change the recovery key. The shares stay valid after a recovery rotation. Custodians set up a new epoch when a share may have been exposed, such as when it was read over a channel that others can see.

### Readiness and custodian changes

The organization is recovery-ready when an active epoch exists and both custodians are active users whose approved key fingerprint equals the fingerprint the share was sent to. Item creation additionally needs a recovery envelope for the vault's current key version under the active epoch. Otherwise the server refuses with 409 `recovery_not_ready` or `recovery_envelope_missing`.

When a custodian is revoked, or an admin approves a replacement key for a custodian, that custodian's share counts as compromised. In the same transaction the server:

- marks the epoch as degraded, so the organization stops being recovery-ready;
- marks the vault `rotation_required`, because the departed share and the remaining one together still open the current recovery envelope.

New items are then blocked and the app shows a banner. To repair, an admin sets up a new epoch with two current custodians. After activation, an owner rotates the vault key, which replaces the last recovery envelope the old shares could open.

### Migration from format 1

Migration `003` is one-way. It deletes format-1 custodian rows and recovery envelopes and clears `recovery_ready`, so item creation stops until custodians enroll under format 2. Existing items and member envelopes are untouched. Rolling back means restoring the `pg_dump` taken before deploy (see BACKUP.md).

## What the server stores

Stored: public keys (identity and recovery), fingerprints, KDF parameters, salts, nonces, ciphertext, sealed envelopes, boxed custodian shares, recovery epochs and their confirmations, vault membership, SHA-256 hashes of recovery challenges, and recovery grants with their expiry.

Not stored and not accepted in import bodies: passphrases, private keys, recovery keys, unwrapped vault keys, account passwords, or card numbers of 13–19 digits. Empty password fields are allowed on import because the browser deletes the password before posting. A non-empty `password`, `secret`, `passphrase`, `private_key`, `cvv`, `pan`, `recovery_key`, `vault_key`, or `token` is rejected.

## Key lifecycle

1. The browser generates the X25519 key pair after invite and MFA.
2. It posts the public key and the two secretboxes. Status becomes `pending_approval`.
3. The sole user may approve their own key while they are the only user. Every later key needs a different active admin. The admin role does not grant vault keys.
4. The owner creates a vault and seals the vault key to themself. That first envelope is accepted once; afterwards the vault is `initialized` and a missing envelope means "not shared with you", never "new vault".
5. An admin sets up a recovery epoch for two custodians. Both custodians confirm. An owner seals the recovery envelope. Item writes open.
6. A replacement public key is a proposal. An admin approves it. Envelopes whose fingerprint does not match the new key are deleted, and the vault is marked `rotation_required`. The person then holds no envelope until a key holder shares the current key to the new public key, or rotates.
7. Revocation deletes memberships and envelopes, revokes sessions, and sets `rotation_required`.

Public-key replacement does not decrypt anything. Recovery does not skip the fingerprint check: unlock compares the opened public key with the approved fingerprint and wipes the private key on mismatch.

## Tests

`web/src/crypto/vault.test.ts` covers the KDF floor, one production Argon2id stretch, secretbox round-trip, recovery-key secretbox, sealed vault-key mismatch, item additional data, and the XOR split with sealed shares. Format 2 adds: split and recombine of a real recovery private key with the derived public key check, a share box from a non-pinned sender refused, a share whose embedded public key differs refused, and a recovery envelope opened with the recombined key.

Format 2 Go tests: challenge sealed with `SealAnonymous` opens with libsodium-compatible output (a fixed test vector from the browser code), a wrong or reused response refused, an expired grant refused, a grant for another vault refused, rotation under a grant makes the custodian an owner and consumes the grant, confirmation with a wrong fingerprint refused, activation only after both confirmations, and revoking a custodian clears readiness and sets `rotation_required`.

Go tests cover authorization, invitation single-use, secret rejection, envelope rotation that keeps the account link, and revocation. They do not reimplement the ciphers.

## Server-side write rules

The server cannot see the vault key, so it enforces who may write and against which state. Every key-affecting write takes the vault row lock (`SELECT ... FOR UPDATE`, 5-second `lock_timeout`, 503 `vault_busy` on timeout) and checks inside the same transaction:

- Member changes, key sharing, recovery envelopes and rotation need a vault owner who holds an envelope for the current key version. The admin role gets no exception.
- Item and envelope writes carry `expected_key_version`. A write prepared under an older key is refused with 409 `stale_key`, so no row ends up labelled with a key version it was not encrypted under.
- Item edits carry the item `version` they read. A stale edit is refused with 409 `item_conflict`.
- Rotation must list exactly the live items with their versions (409 `items_changed` or `item_conflict` otherwise), one envelope per member to an approved fingerprint, and a recovery envelope for the active epoch.
- A rotation under a recovery grant is the one exception to the owner gate. See "Recovering".
- A vault always keeps an owner: removing, demoting or revoking its last owner is refused with 409 `last_vault_owner`.

## Verifying recipient keys

The server's public-key list is not trusted on its own. Before the browser seals a vault key (sharing, rotation) or a recovery share (custodian setup) to a public key, or seals a recovery envelope to the organization recovery key, someone in that browser compares the key's SHA-256 fingerprint with its owner out of band and types the last of its sixteen 4-character groups. The browser then pins `user → fingerprint` in `localStorage` for the signed-in user. A pinned key is used without asking again; a different fingerprint for the same person is shown as a changed key and blocks sealing until it is verified again. Your own key is pinned when you unlock, because the browser has just checked it against the approved fingerprint. Pins are per browser: a new device asks again, which is safe, only slower. The recovery key is pinned per organization: custodians pin it when they confirm their share, and other owners verify it against a custodian the first time they rotate.
