# Recovery runbook

Read this before the first real password is stored. If every member who holds the vault key loses both their passphrase and their personal recovery key, and the two recovery custodians cannot both take part, those vault items are permanently unreadable. Nobody with database access can reconstruct them.

Resetting a password in Authentik does not unlock the vault.

## Personal recovery

Enrollment creates two secretboxes of the same X25519 private key:

- one under the Argon2id passphrase;
- one under a 32-byte recovery key.

The interface shows the recovery key once, in standard base64. Store it outside the application, separately from the passphrase. The server stores only the secretbox.

To unlock after a lost passphrase:

1. Sign in through Authentik. The account still needs a valid session and an approved key.
2. Open the Vault page and choose "Unlock with recovery key".
3. Paste the recovery key. The browser opens the second secretbox and checks the fingerprint of the approved public key. A mismatch wipes the private key and stops.

This does not replace a rejected or revoked key. A new public key is a proposal and still needs a different admin to approve it.

## Changing a passphrase

Vault › Recovery › Change your passphrase rewraps the same private key under the new passphrase. The public key, its approval and every envelope stay as they are, so nothing has to be shared again. The personal recovery key keeps working.

## Setting up organization recovery

New passwords stay blocked until organization recovery is set up and the vault key is sealed to it. Reading and editing existing passwords never depends on it.

Recovery uses a recovery key: an X25519 key pair whose private half is split between two custodians. The public half lets any owner seal the vault key for recovery without the custodians. The design is in `docs/CRYPTO.md` › "Organization recovery".

1. **Choose custodians.** Two different people with approved keys. Prefer two people other than the admin doing the setup, because that admin's browser briefly holds the whole recovery key.
2. **Set up** (an admin, Vault › Recovery › Set up recovery). Verify both custodians' fingerprints when asked. The browser creates the recovery key, splits it, sends each custodian their share in a box only they can open, pins the recovery key fingerprint, and wipes the private key. The status shows `pending`.
3. **Confirm** (each custodian, Vault). A custodian who is not a vault member still unlocks with their own passphrase; the page then shows their recovery work instead of the vault. Verify the admin who set it up if asked, then choose Confirm my share. The browser checks that the share came from that admin and belongs to this recovery key. After both confirm, the status shows `confirmed`.
4. **Seal** (a vault owner who holds the key, Vault › Recovery › Seal vault key). This switches the new recovery key on, retires the previous one and deletes its envelopes. The status shows `active · ready`, and new passwords can be saved.

Each setup gets the next number (`r1`, `r2`, …). Every browser that has seen recovery key `rN` refuses an older one. An owner whose browser has not seen the recovery key yet is asked to verify its fingerprint with a custodian the first time they seal or rotate.

## Recovering the vault

Use this when nobody who holds the vault key can unlock it. For example, the only owner lost both their passphrase and their personal recovery key. If any owner can still unlock, they rotate instead (below); that needs no custodian.

1. **The other custodian** unlocks, opens Vault, and chooses Show my share. They read it to the recovering custodian directly: in person or on a call. Do not send it through chat, email or a ticket. They choose Hide share afterwards.
2. **The recovering custodian** unlocks, opens Vault, and chooses Start recovery. They type the other share. The browser combines the shares and checks them against the recovery key fingerprint. A wrong share fails in the browser, and nothing is sent.
3. The browser answers the server's challenge with the recovery key. That opens a **15-minute recovery window** for one rotation. The server allows five attempts per custodian per hour.
4. The browser opens the vault key. The custodian chooses who keeps access. Only people whose key this browser has verified can be kept; the others can be added back later.
5. **Rotate and take over.** Every password is re-encrypted under a new vault key. The custodian becomes a vault owner, and people left out lose access.

**A recovery uses up the recovery key.** Both shares were in one browser and one was read aloud, so assume they were copied. After a recovery the status shows `spent` and new passwords are blocked. Set up recovery again with a new recovery key (above), ideally with different custodians or at least fresh shares, and seal the vault key to it.

## Rotating the vault key

An owner who holds the vault key rotates from Vault › Recovery › Rotate key. Every member's key must be verified in that browser. If recovery is usable, the new vault key is sealed to the recovery key too; no custodian has to be present. If recovery is degraded, spent or not set up, the new key goes to members only.

## When a custodian leaves

Revoking a custodian, approving a replacement key for a custodian, or revoking the admin who set up the current recovery key **degrades** recovery:

- The status shows `degraded`. Recovery is refused, and new passwords are blocked.
- The vault is marked `rotation_required`, because the departed person's share and the remaining one could still open the current recovery envelope.

Repair promptly. Until then, only members who hold the vault key can open the vault.

1. An admin sets up a new recovery key with two current custodians.
2. Both custodians confirm.
3. An owner seals the vault key, which switches the new recovery key on.
4. The owner then rotates the vault key. That replaces the last vault key the old shares could reach.

## Lost device

1. Revoke the session by logging out other browsers if the person still has one, or revoke the user if the device is not recoverable.
2. The ciphertext on the device is still protected by the passphrase and the recovery key. Change the passphrase by enrolling a new identity only when you also still have a way to read the vault and rotate it. A new identity without the old vault key cannot read old items.
3. If the device may have been used while the vault was unlocked, rotate the external passwords too. This application cannot reach into the services those passwords belong to.

## Employee departure

1. An admin revokes the user. Sessions end, vault membership and envelopes for that user are deleted, and the vault is marked `rotation_required`. If the person was a custodian or set up the current recovery key, recovery is degraded too (see "When a custodian leaves").
2. An owner rotates the vault key. People who were removed do not get a new envelope.
3. Change the external credentials the person could already see. Rotation does not change passwords at third parties.

The last active admin cannot be revoked. Appoint another admin first.

## Disaster recovery

Restore Postgres from the dump in `BACKUP.md`. That restores ciphertext, metadata, users, and sessions. It does not restore a passphrase or a share that was never in the database.

After a restore:

- Invalidate sessions if the dump is old enough that stolen cookies might still be inside their lifetime. Revoke the affected users or wait out `SESSION_TTL` (default 12 hours) and delete `sessions`.
- Members unlock with their passphrase or personal recovery key.
- If nobody who holds the vault key can unlock, the custodians recover the vault (above). A custodian who lost both their passphrase and their personal recovery key cannot open their share, and the other custodian cannot finish alone.
- A restore can bring back an older recovery key. Browsers that saw a newer one refuse it. Set up recovery again if the restored recovery key is older than the one custodians last confirmed.

## No break-glass account

There is no break-glass account and no server-side master key. Do not add one. Organization recovery is the only way to open a vault that no member can unlock.

## What not to do

- Do not email recovery keys or shares.
- Do not paste a share into an admin tool or a log.
- Do not approve a replacement public key in order to skip an existing fingerprint. Approval publishes a new key. It does not decrypt old envelopes. The holder of the new key gets a new envelope when a key holder shares the vault again or rotates.
- Do not keep a revealed share on screen, in a screenshot or in a password manager. A share is half of the recovery key.
- Do not describe a database restore as a vault unlock.
