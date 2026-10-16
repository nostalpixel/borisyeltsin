# Cryptographic design

BorisEltsyn uses libsodium constructions only. This document records the choices that are already in the client and the server checks around them. It is not a new protocol.

Do not put real organizational credentials in the vault until someone other than the implementer has reviewed this design.

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
| Organization recovery | 2-of-2 additive XOR split of a 32-byte key. Each share is `crypto_box_seal`ed to one custodian. The vault key is `secretbox`ed under the combined key. |

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

Before the server accepts vault items, two things must be true:

1. `organizations.recovery_ready` is set.
2. A recovery envelope exists for the current vault key version.

`recovery_ready` is set when two distinct active users, each with an approved public key, are recorded as custodians at share indexes 1 and 2.

The split is textbook additive secret sharing:

- `share1` is 32 random bytes.
- `share2` is `vault_recovery_key XOR share1`.
- Either share alone is indistinguishable from random while the other share stays secret.
- `share1 XOR share2` restores the 32-byte key.

Each share is sealed to that custodian's approved public key. The browser posts only the sealed shares. `GET /api/v1/recovery/share` returns the caller's sealed share and nobody else's. Combining the shares requires both plaintext shares in one browser. The server never stores the combined key.

The same combined key wraps the current vault key in a secretbox. Rotation builds a new vault key, re-encrypts every item under the next version, seals a new envelope for every current member, and secretboxes the new vault key under the same combined recovery key. Item ids are reused so account links survive. The write is one transaction. A failed request leaves the previous `key_version` in place.

## What the server stores

Stored: public keys, fingerprints, KDF parameters, salts, nonces, ciphertext, sealed envelopes, sealed shares, vault membership, and the `recovery_ready` flag.

Not stored and not accepted in import bodies: passphrases, private keys, recovery keys, unwrapped vault keys, account passwords, or card numbers of 13–19 digits. Empty password fields are allowed on import because the browser deletes the password before posting. A non-empty `password`, `secret`, `passphrase`, `private_key`, `cvv`, `pan`, `recovery_key`, `vault_key`, or `token` is rejected.

## Key lifecycle

1. The browser generates the X25519 key pair after invite and MFA.
2. It posts the public key and the two secretboxes. Status becomes `pending_approval`.
3. The sole user may approve their own key while they are the only user. Every later key needs a different active admin. The admin role does not grant vault keys.
4. The owner creates a vault and seals the vault key to themself.
5. Two custodians enroll. The owner posts the recovery envelope. Item writes open.
6. A replacement public key is a proposal. An admin approves it. Envelopes whose fingerprint does not match the new key are deleted, and the vault is marked `rotation_required`. The old private key still opens the remaining envelopes until rotation.
7. Revocation deletes memberships and envelopes, revokes sessions, and sets `rotation_required`.

Public-key replacement does not decrypt anything. Recovery does not skip the fingerprint check: unlock compares the opened public key with the approved fingerprint and wipes the private key on mismatch.

## Tests

`web/src/crypto/vault.test.ts` covers the KDF floor, one production Argon2id stretch, secretbox round-trip, recovery-key secretbox, sealed vault-key mismatch, item additional data, and the XOR split with sealed shares.

Go tests cover authorization, invitation single-use, secret rejection, envelope rotation that keeps the account link, and revocation. They do not reimplement the ciphers.
