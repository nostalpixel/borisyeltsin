# Recovery runbook

Read this before the first real password is stored. If the passphrase, the personal recovery key, and both organization shares are lost, those vault items are permanently unreadable. Nobody with database access can reconstruct them.

Resetting a password in Authentik does not unlock the vault.

## Personal recovery

Enrollment creates two secretboxes of the same X25519 private key:

- one under the Argon2id passphrase;
- one under a 32-byte recovery key.

The interface shows the recovery key once, in standard base64. Store it outside the application, separately from the passphrase. The server stores only the secretbox.

To unlock after a lost passphrase:

1. Sign in through Authentik. The account still needs a valid session and an approved key.
2. Open the vault page and choose "Открыть ключом восстановления".
3. Paste the recovery key. The browser opens the second secretbox and checks the fingerprint of the approved public key. A mismatch wipes the private key and stops.

This does not replace a rejected or revoked key. A new public key is a proposal and still needs a different admin to approve it.

## Organization recovery enrollment

Vault items stay blocked until two custodians exist and a recovery envelope is stored.

1. Two active members each have an approved public key. The first admin cannot finish this step alone.
2. A member who already holds the vault key opens the vault and picks two different people.
3. The browser generates a 32-byte organization key, splits it with XOR, and seals share 1 to the first custodian and share 2 to the second. It posts the sealed shares.
4. The browser secretboxes the current vault key under the organization key and posts that envelope. It then zeroes the organization key and both shares.

`GET /api/v1/recovery/share` returns only the sealed share of the caller.

## Using the organization shares

Both custodians bring their unsealed shares to one browser. One share is not enough, and the server will not combine them.

1. Each custodian unlocks their own identity on a machine they trust, reveals their share, and carries it to the recovery machine. Prefer a machine one of them controls. Do not send shares through the application chat, email, or a ticket.
2. On the vault page, paste share 1 and share 2 into the rotation form. Rotation is also the emergency path: it checks that the shares combine, builds a new vault key, re-encrypts items, and writes new member envelopes plus a new recovery envelope.
3. Clear the share fields. The people who saw the shares should assume those copies exist until they destroy them.

Rotation refuses to run unless the organization is `recovery_ready` and the posted envelopes match the current members and their approved fingerprints.

## Lost device

1. Revoke the session by logging out other browsers if the person still has one, or revoke the user if the device is not recoverable.
2. The ciphertext on the device is still protected by the passphrase and the recovery key. Change the passphrase by enrolling a new identity only when you also still have a way to read the vault and rotate it. A new identity without the old vault key cannot read old items.
3. If the device may have been used while the vault was unlocked, rotate the external passwords too. This application cannot reach into the services those passwords belong to.

## Employee departure

1. An admin revokes the user. Sessions end, vault membership and envelopes for that user are deleted, and the vault is marked `rotation_required`.
2. Remaining members rotate the vault key with both organization shares. People who were removed do not get a new envelope.
3. Change the external credentials the person could already see. Rotation does not change passwords at third parties.

The last active admin cannot be revoked. Appoint another admin first.

## Disaster recovery

Restore Postgres from the dump in `BACKUP.md`. That restores ciphertext, metadata, users, and sessions. It does not restore a passphrase or a share that was never in the database.

After a restore:

- Invalidate sessions if the dump is old enough that stolen cookies might still be inside their lifetime. Revoke the affected users or wait out `SESSION_TTL` (default 12 hours) and delete `sessions`.
- Members unlock with their passphrase or personal recovery key.
- If a member's private key is gone but both shares remain, the remaining custodian who can still open their share, together with the other share, can rotate. A custodian who lost their private key and their personal recovery key cannot open their share. The other custodian cannot finish alone.

## Loss of the last vault member

If no remaining member can open an envelope, recovery depends on the two sealed shares and on at least one custodian who can still open their share. The second share must still be in someone's possession in plaintext, or still sealed to a custodian who can open it.

There is no break-glass account. Do not add one.

## What not to do

- Do not email recovery keys or shares.
- Do not paste a share into an admin tool or a log.
- Do not approve a replacement public key in order to skip an existing fingerprint. Approval publishes a new key. It does not decrypt old envelopes. The holder of the new key gets a new envelope only at the next rotation, which still needs both shares.
- Do not describe a database restore as a vault unlock.
