import { ApiError, api } from "../api";
import type { PublicKey, VaultInfo } from "../types";
import {
  KDF_MEMLIMIT,
  KDF_OPSLIMIT,
  boxShare,
  combineShares,
  decryptItem,
  deriveKek,
  encryptItem,
  fingerprint,
  fromB64,
  identityKeypair,
  openRecoveryEnvelope,
  openSealed,
  openShare,
  openVaultKey,
  passphraseKek,
  passwordRecord,
  publicFromPrivate,
  randomBytes,
  readPassword,
  recoveryKeypair,
  sealRecoveryEnvelope,
  sealVaultKey,
  secretbox,
  secretboxOpen,
  sodiumReady,
  splitKey,
  toB64,
  type SharePayload,
} from "./vault";
import sodium from "libsodium-wrappers-sumo";
import { pinRecoveryKey, recoveryPinState, requireRecoveryVerified, requireVerified } from "./pins";

export type IdentityRecord = {
  status: string;
  fingerprint?: string;
  public_key?: string;
  kdf_opslimit?: number;
  kdf_memlimit?: number;
  kdf_salt?: string;
  private_key_nonce?: string;
  private_key_ciphertext?: string;
  recovery_nonce?: string;
  recovery_ciphertext?: string;
};

export type HeldKeys = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  fingerprint: string;
};

export async function createIdentity(passphrase: string): Promise<{ body: Record<string, string | number>; recoveryKey: string }> {
  await sodiumReady();
  const pair = identityKeypair();
  const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES);
  const kek = passphraseKek(passphrase, salt);
  const backup = secretbox(pair.privateKey, kek);
  const recovery = randomBytes(32);
  const recoveryBox = secretbox(pair.privateKey, recovery);
  const fp = await fingerprint(pair.publicKey);
  sodium.memzero(kek);
  return {
    recoveryKey: toB64(recovery),
    body: {
      public_key: toB64(pair.publicKey),
      kdf_opslimit: KDF_OPSLIMIT,
      kdf_memlimit: KDF_MEMLIMIT,
      kdf_salt: toB64(salt),
      private_key_nonce: toB64(backup.nonce),
      private_key_ciphertext: toB64(backup.ciphertext),
      recovery_nonce: toB64(recoveryBox.nonce),
      recovery_ciphertext: toB64(recoveryBox.ciphertext),
      fingerprint: fp,
    },
  };
}

export async function unlockIdentity(passphrase: string): Promise<HeldKeys> {
  await sodiumReady();
  const me = await api<IdentityRecord>("/api/v1/crypto/me");
  if (me.status !== "approved" || !me.public_key || !me.kdf_salt || !me.private_key_nonce || !me.private_key_ciphertext) {
    throw new Error("key_not_approved");
  }
  if ((me.kdf_opslimit ?? 0) < KDF_OPSLIMIT || (me.kdf_memlimit ?? 0) < KDF_MEMLIMIT) {
    throw new Error("weak_kdf");
  }
  const kek = deriveKek(passphrase, fromB64(me.kdf_salt), me.kdf_opslimit ?? KDF_OPSLIMIT, me.kdf_memlimit ?? KDF_MEMLIMIT);
  let privateKey: Uint8Array;
  try {
    privateKey = secretboxOpen({ nonce: fromB64(me.private_key_nonce), ciphertext: fromB64(me.private_key_ciphertext) }, kek);
  } catch {
    sodium.memzero(kek);
    throw new Error("bad_passphrase");
  }
  sodium.memzero(kek);
  const publicKey = fromB64(me.public_key);
  const fp = await fingerprint(publicKey);
  if (fp !== me.fingerprint) {
    sodium.memzero(privateKey);
    throw new Error("fingerprint_mismatch");
  }
  return { publicKey, privateKey, fingerprint: fp };
}

export async function unlockWithRecoveryKey(recoveryKey: string): Promise<HeldKeys> {
  await sodiumReady();
  const me = await api<IdentityRecord>("/api/v1/crypto/me");
  if (me.status !== "approved" || !me.public_key || !me.recovery_nonce || !me.recovery_ciphertext) {
    throw new Error("key_not_approved");
  }
  const key = fromB64(recoveryKey.trim());
  let privateKey: Uint8Array;
  try {
    if (key.length !== sodium.crypto_secretbox_KEYBYTES) {
      throw new Error("bad_recovery_key");
    }
    privateKey = secretboxOpen({ nonce: fromB64(me.recovery_nonce), ciphertext: fromB64(me.recovery_ciphertext) }, key);
  } catch (err) {
    if (err instanceof Error && err.message === "bad_recovery_key") {
      throw err;
    }
    throw new Error("bad_recovery_key");
  } finally {
    sodium.memzero(key);
  }
  const publicKey = fromB64(me.public_key);
  const fp = await fingerprint(publicKey);
  if (fp !== me.fingerprint) {
    sodium.memzero(privateKey);
    throw new Error("fingerprint_mismatch");
  }
  return { publicKey, privateKey, fingerprint: fp };
}

export function lockKeys(keys: HeldKeys | null) {
  if (!keys) return;
  sodium.memzero(keys.privateKey);
}

export async function readVaultKey(keys: HeldKeys, vaultId: string, keyVersion: number): Promise<Uint8Array> {
  await sodiumReady();
  const env = await api<{ ciphertext: string; key_version: number }>(`/api/v1/vaults/${vaultId}/envelope`);
  return openVaultKey(fromB64(env.ciphertext), keys.publicKey, keys.privateKey, vaultId, env.key_version || keyVersion);
}

export async function writeOwnerEnvelope(keys: HeldKeys, userId: string, vaultId: string, keyVersion: number, vaultKey: Uint8Array) {
  await sodiumReady();
  const sealed = sealVaultKey(vaultId, keyVersion, vaultKey, keys.publicKey);
  await api(`/api/v1/vaults/${vaultId}/envelopes`, "POST", {
    user_id: userId,
    fingerprint: keys.fingerprint,
    ciphertext: toB64(sealed),
    expected_key_version: keyVersion,
  });
}

// ensureVault opens the vault the caller belongs to. It creates one only when
// the organization has none yet; a vault the caller is not in is "no access",
// never a reason to start a second vault.
export async function ensureVault(name = "Services"): Promise<VaultInfo> {
  const listed = await api<{ vaults: VaultInfo[] }>("/api/v1/vaults");
  const mine = listed.vaults.find((vault) => vault.role !== "");
  if (mine) {
    return mine;
  }
  if (listed.vaults.length > 0) {
    throw new ApiError(404, "no_access");
  }
  const created = await api<{ id: string; name: string; key_version: number }>("/api/v1/vaults", "POST", { name });
  return { id: created.id, name: created.name, key_version: created.key_version, rotation_required: false, role: "owner", initialized: false };
}

export async function newVaultKey(): Promise<Uint8Array> {
  await sodiumReady();
  return randomBytes(32);
}

export type CustodianChoice = { user_id: string; fingerprint: string; public_key: string };

// shareVaultKey seals the current vault key to a member whose key this
// browser has verified. It never seals to a key it only got from the server.
export async function shareVaultKey(viewerId: string, vault: VaultInfo, vaultKey: Uint8Array, member: CustodianChoice) {
  requireVerified(viewerId, member.user_id, member.fingerprint);
  await sodiumReady();
  const sealed = sealVaultKey(vault.id, vault.key_version, vaultKey, fromB64(member.public_key));
  await api(`/api/v1/vaults/${vault.id}/envelopes`, "POST", {
    user_id: member.user_id,
    fingerprint: member.fingerprint,
    ciphertext: toB64(sealed),
    expected_key_version: vault.key_version,
  });
}

// changePassphrase rewraps the same private key under a new passphrase. The
// public key, its approval and every envelope stay as they are.
export async function changePassphrase(keys: HeldKeys, passphrase: string) {
  await sodiumReady();
  const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES);
  const kek = passphraseKek(passphrase, salt);
  const backup = secretbox(keys.privateKey, kek);
  sodium.memzero(kek);
  await api("/api/v1/crypto/identity/passphrase", "PUT", {
    fingerprint: keys.fingerprint,
    kdf_opslimit: KDF_OPSLIMIT,
    kdf_memlimit: KDF_MEMLIMIT,
    kdf_salt: toB64(salt),
    private_key_nonce: toB64(backup.nonce),
    private_key_ciphertext: toB64(backup.ciphertext),
  });
}

// Organization recovery, format 2. docs/CRYPTO.md "Organization recovery" is
// the specification; each function names the step it implements.

export type Custodian = {
  share_index: number;
  user_id: string;
  display_name: string;
  email: string;
  fingerprint: string;
  confirmed: boolean;
  active: boolean;
};

export type Epoch = {
  epoch: number;
  status: "pending" | "confirmed" | "active" | "degraded" | "spent" | "retired";
  public_key: string;
  fingerprint: string;
  created_by: string;
  creator_public_key: string;
  creator_fingerprint: string;
  custodians: Custodian[];
};

export type RecoveryInfo = {
  organization_id: string;
  recovery_ready: boolean;
  max_epoch: number;
  vaults: { id: string; name: string }[];
  current: Epoch | null;
  next: Epoch | null;
};

export function loadRecovery(): Promise<RecoveryInfo> {
  return api<RecoveryInfo>("/api/v1/recovery");
}

// sealTarget mirrors the server: a confirmed epoch waiting for its first
// envelope, else the active epoch while recovery is ready, else none.
export function sealTarget(info: RecoveryInfo): Epoch | null {
  if (info.next?.status === "confirmed") return info.next;
  if (info.recovery_ready && info.current?.status === "active") return info.current;
  return null;
}

// setupRecovery generates the recovery key, splits its private half and
// boxes one share to each custodian from this admin's identity key.
export async function setupRecovery(viewerId: string, keys: HeldKeys, info: RecoveryInfo, first: CustodianChoice, second: CustodianChoice) {
  requireVerified(viewerId, first.user_id, first.fingerprint);
  requireVerified(viewerId, second.user_id, second.fingerprint);
  if (first.user_id === second.user_id || first.fingerprint === second.fingerprint) {
    throw new Error("custodians_not_distinct");
  }
  await sodiumReady();
  const epoch = info.max_epoch + 1;
  const recovery = recoveryKeypair();
  const recoveryFingerprint = await fingerprint(recovery.publicKey);
  const { share1, share2 } = splitKey(recovery.privateKey);
  sodium.memzero(recovery.privateKey);
  try {
    const custodians = [first, second].map((custodian, index) => {
      const payload: SharePayload = {
        v: 2,
        org_id: info.organization_id,
        epoch,
        share_index: index + 1,
        sender_user_id: viewerId,
        sender_fingerprint: keys.fingerprint,
        custodian_user_id: custodian.user_id,
        custodian_fingerprint: custodian.fingerprint,
        share: toB64(index === 0 ? share1 : share2),
        recovery_public_key: toB64(recovery.publicKey),
      };
      const boxed = boxShare(payload, fromB64(custodian.public_key), keys.privateKey);
      return {
        user_id: custodian.user_id,
        share_index: index + 1,
        fingerprint: custodian.fingerprint,
        nonce: toB64(boxed.nonce),
        share_ciphertext: toB64(boxed.ciphertext),
      };
    });
    await api("/api/v1/recovery/epochs", "POST", { epoch, public_key: toB64(recovery.publicKey), custodians });
  } finally {
    sodium.memzero(share1);
    sodium.memzero(share2);
  }
  // This browser made the key, so it knows the fingerprint is genuine.
  pinRecoveryKey(viewerId, info.organization_id, recoveryFingerprint, epoch);
}

type ShareRow = {
  epoch: number;
  status: Epoch["status"];
  share_index: number;
  fingerprint: string;
  nonce: string;
  share_ciphertext: string;
  confirmed: boolean;
  public_key: string;
  recovery_fingerprint: string;
  created_by: string;
  creator_public_key: string;
  creator_fingerprint: string;
};

// openMyShare is "Custodian shares", confirmation steps 1 to 3: the box must
// open with the pinned creator's key and every field must match.
async function openMyShare(viewerId: string, keys: HeldKeys, orgId: string, epoch?: number): Promise<{ row: ShareRow; payload: SharePayload }> {
  await sodiumReady();
  const row = await api<ShareRow>(`/api/v1/recovery/share${epoch ? `?epoch=${epoch}` : ""}`);
  const creatorPublic = fromB64(row.creator_public_key);
  if ((await fingerprint(creatorPublic)) !== row.creator_fingerprint) {
    throw new Error("fingerprint_mismatch");
  }
  requireVerified(viewerId, row.created_by, row.creator_fingerprint);
  let payload: SharePayload;
  try {
    payload = openShare({ nonce: fromB64(row.nonce), ciphertext: fromB64(row.share_ciphertext) }, creatorPublic, keys.privateKey);
  } catch {
    throw new Error("share_mismatch");
  }
  const matches =
    payload.org_id === orgId &&
    payload.epoch === row.epoch &&
    payload.share_index === row.share_index &&
    payload.sender_user_id === row.created_by &&
    payload.sender_fingerprint === row.creator_fingerprint &&
    payload.custodian_user_id === viewerId &&
    payload.custodian_fingerprint === keys.fingerprint &&
    payload.recovery_public_key === row.public_key &&
    (await fingerprint(fromB64(row.public_key))) === row.recovery_fingerprint;
  if (!matches) {
    throw new Error("share_mismatch");
  }
  return { row, payload };
}

// confirmMyShare is confirmation step 4: pin the recovery key and report it.
export async function confirmMyShare(viewerId: string, keys: HeldKeys, orgId: string) {
  const { row } = await openMyShare(viewerId, keys, orgId);
  if (row.status !== "pending" || row.confirmed) {
    throw new Error("nothing_to_confirm");
  }
  pinRecoveryKey(viewerId, orgId, row.recovery_fingerprint, row.epoch);
  await api("/api/v1/recovery/confirm", "POST", { epoch: row.epoch, fingerprint: row.recovery_fingerprint });
}

// revealMyShare returns this custodian's share as text, to read to the other
// custodian during a recovery.
export async function revealMyShare(viewerId: string, keys: HeldKeys, orgId: string, epoch: number): Promise<string> {
  const { payload } = await openMyShare(viewerId, keys, orgId, epoch);
  return payload.share;
}

// sealRecovery seals the current vault key to the recovery public key. For a
// confirmed epoch this first envelope is what activates it.
export async function sealRecovery(viewerId: string, orgId: string, vault: VaultInfo, vaultKey: Uint8Array, target: Epoch) {
  await api(`/api/v1/vaults/${vault.id}/recovery-envelope`, "POST", {
    epoch: target.epoch,
    ciphertext: await recoveryEnvelopeFor(viewerId, orgId, vault.id, vault.key_version, vaultKey, target),
    expected_key_version: vault.key_version,
  });
}

async function recoveryEnvelopeFor(viewerId: string, orgId: string, vaultId: string, keyVersion: number, vaultKey: Uint8Array, target: Epoch): Promise<string> {
  await sodiumReady();
  const recoveryPublic = fromB64(target.public_key);
  if ((await fingerprint(recoveryPublic)) !== target.fingerprint) {
    throw new Error("fingerprint_mismatch");
  }
  requireRecoveryVerified(viewerId, orgId, target.fingerprint, target.epoch);
  const context = { org_id: orgId, vault_id: vaultId, key_version: keyVersion, epoch: target.epoch, recovery_fingerprint: target.fingerprint };
  return toB64(sealRecoveryEnvelope(context, vaultKey, recoveryPublic));
}

export type RecoveredVault = {
  vaultId: string;
  keyVersion: number;
  oldKey: Uint8Array;
  expiresAt: string;
  members: { user_id: string; role: string; display_name: string; email: string }[];
};

// proveRecovery is "Recovering", steps 1 to 4: combine the shares, answer the
// server's challenge, and open the vault key from the recovery envelope.
export async function proveRecovery(viewerId: string, keys: HeldKeys, info: RecoveryInfo, vaultId: string, otherShare: string): Promise<RecoveredVault> {
  const current = info.current;
  if (!info.recovery_ready || !current || current.status !== "active") {
    throw new Error("recovery_unavailable");
  }
  const pin = recoveryPinState(viewerId, info.organization_id, current.fingerprint, current.epoch);
  if (pin.state === "rollback") throw new Error("recovery_rollback");
  if (pin.state === "changed") throw new Error("recovery_key_changed");
  const { payload } = await openMyShare(viewerId, keys, info.organization_id, current.epoch);
  const mine = fromB64(payload.share);
  let other: Uint8Array;
  try {
    other = fromB64(otherShare.replace(/\s+/g, ""));
  } catch {
    sodium.memzero(mine);
    throw new Error("bad_share");
  }
  if (other.length !== 32) {
    sodium.memzero(mine);
    throw new Error("bad_share");
  }
  const privateKey = combineShares(mine, other);
  sodium.memzero(mine);
  sodium.memzero(other);
  try {
    const publicKey = publicFromPrivate(privateKey);
    if ((await fingerprint(publicKey)) !== current.fingerprint) {
      throw new Error("shares_do_not_match");
    }
    // The shares came from an authenticated box and the other custodian, so
    // the recombined key is genuine; pin it for this browser.
    pinRecoveryKey(viewerId, info.organization_id, current.fingerprint, current.epoch);

    const challenge = await api<{ challenge_id: string; epoch: number; sealed: string }>("/api/v1/recovery/challenge", "POST", { vault_id: vaultId });
    const plain = openSealed(fromB64(challenge.sealed), publicKey, privateKey);
    const fields = JSON.parse(sodium.to_string(plain)) as { challenge_id: string; org_id: string; vault_id: string; epoch: number; custodian_id: string };
    if (
      fields.challenge_id !== challenge.challenge_id ||
      fields.org_id !== info.organization_id ||
      fields.vault_id !== vaultId ||
      fields.epoch !== current.epoch ||
      fields.custodian_id !== viewerId
    ) {
      throw new Error("challenge_mismatch");
    }
    const grant = await api<{ expires_at: string }>("/api/v1/recovery/grant", "POST", { challenge_id: challenge.challenge_id, response: toB64(plain) });

    const detail = await api<{ key_version: number; members: RecoveredVault["members"] }>(`/api/v1/vaults/${vaultId}`);
    const env = await api<{ key_version: number; epoch: number; ciphertext: string }>(`/api/v1/vaults/${vaultId}/recovery-envelope`);
    const oldKey = openRecoveryEnvelope(fromB64(env.ciphertext), publicKey, privateKey, {
      org_id: info.organization_id,
      vault_id: vaultId,
      key_version: detail.key_version,
      epoch: current.epoch,
      recovery_fingerprint: current.fingerprint,
    });
    return { vaultId, keyVersion: detail.key_version, oldKey, expiresAt: grant.expires_at, members: detail.members };
  } finally {
    sodium.memzero(privateKey);
  }
}

// finishRecovery is step 5: rotate under the grant, keeping the chosen
// verified members, and become an owner. No recovery envelope: the key is spent.
export async function finishRecovery(viewerId: string, keys: HeldKeys, recovered: RecoveredVault, keep: string[]) {
  await sodiumReady();
  const vault = { id: recovered.vaultId, key_version: recovered.keyVersion } as VaultInfo;
  try {
    const keysList = await api<{ keys: PublicKey[] }>("/api/v1/crypto/keys");
    const recipients = [...new Set([viewerId, ...keep])].map((id) => {
      if (id === viewerId) return { user_id: id, fingerprint: keys.fingerprint, public_key: toB64(keys.publicKey) };
      const pub = keysList.keys.find((row) => row.user_id === id && row.key_status === "approved");
      if (!pub) throw new Error("fingerprint_mismatch");
      requireVerified(viewerId, id, pub.fingerprint);
      return pub;
    });
    return await rotateWith(vault, recovered.oldKey, recipients, null);
  } finally {
    sodium.memzero(recovered.oldKey);
  }
}

export type VaultItems = {
  passwords: Record<string, string>;
  // Item versions as last read. Edits send them back so a stale edit is refused.
  versions: Record<string, number>;
};

type ItemRow = { id: string; key_version: number; version: number; nonce: string; ciphertext: string };

export async function loadPasswords(vault: VaultInfo, vaultKey: Uint8Array): Promise<VaultItems> {
  await sodiumReady();
  const listed = await api<{ items: ItemRow[] }>(`/api/v1/vaults/${vault.id}/items`);
  const out: Record<string, string> = {};
  const versions: Record<string, number> = {};
  for (const item of listed.items) {
    versions[item.id] = item.version;
    try {
      const plain = decryptItem(vault.id, item.id, item.key_version, vaultKey, {
        nonce: fromB64(item.nonce),
        ciphertext: fromB64(item.ciphertext),
      });
      out[item.id] = readPassword(plain);
    } catch {
      out[item.id] = "";
    }
  }
  return { passwords: out, versions };
}

export async function savePassword(
  vault: VaultInfo,
  vaultKey: Uint8Array,
  accountId: string,
  itemId: string | null,
  password: string,
  version: number | undefined,
): Promise<{ id: string; version: number }> {
  await sodiumReady();
  const id = itemId || crypto.randomUUID();
  const boxed = encryptItem(vault.id, id, vault.key_version, vaultKey, passwordRecord(password));
  const body = { nonce: toB64(boxed.nonce), ciphertext: toB64(boxed.ciphertext), expected_key_version: vault.key_version };
  if (itemId) {
    const saved = await api<{ version: number }>(`/api/v1/vaults/${vault.id}/items/${id}`, "PUT", { ...body, version: version ?? 0 });
    return { id, version: saved.version };
  }
  const created = await api<{ version: number }>(`/api/v1/vaults/${vault.id}/items`, "POST", { id, ...body });
  await api(`/api/v1/accounts/${accountId}/vault-link`, "POST", { vault_id: vault.id, vault_item_id: id });
  return { id, version: created.version };
}

// rotateVault re-encrypts every item under a new key, seals it to every member
// and, when recovery is usable, to the recovery key. No custodian is needed.
export async function rotateVault(viewerId: string, orgId: string, vault: VaultInfo, vaultKey: Uint8Array, target: Epoch | null) {
  await sodiumReady();
  const detail = await api<{ members: { user_id: string }[] }>(`/api/v1/vaults/${vault.id}`);
  const keysList = await api<{ keys: PublicKey[] }>("/api/v1/crypto/keys");
  const recipients = detail.members.map((member) => {
    const pub = keysList.keys.find((row) => row.user_id === member.user_id && row.key_status === "approved");
    if (!pub) {
      throw new Error("fingerprint_mismatch");
    }
    requireVerified(viewerId, member.user_id, pub.fingerprint);
    return pub;
  });
  const recovery = target ? { viewerId, orgId, target } : null;
  const next = await rotateWith(vault, vaultKey, recipients, recovery);
  sodium.memzero(vaultKey);
  return next;
}

async function rotateWith(
  vault: VaultInfo,
  vaultKey: Uint8Array,
  recipients: { user_id: string; fingerprint: string; public_key: string }[],
  recovery: { viewerId: string; orgId: string; target: Epoch } | null,
) {
  const nextKey = randomBytes(32);
  const nextVersion = vault.key_version + 1;
  const listed = await api<{ items: ItemRow[] }>(`/api/v1/vaults/${vault.id}/items`);
  const items = listed.items.map((item) => {
    const plain = decryptItem(vault.id, item.id, item.key_version, vaultKey, {
      nonce: fromB64(item.nonce),
      ciphertext: fromB64(item.ciphertext),
    });
    const boxed = encryptItem(vault.id, item.id, nextVersion, nextKey, plain);
    return { id: item.id, version: item.version, nonce: toB64(boxed.nonce), ciphertext: toB64(boxed.ciphertext) };
  });
  const envelopes = recipients.map((pub) => ({
    user_id: pub.user_id,
    fingerprint: pub.fingerprint,
    ciphertext: toB64(sealVaultKey(vault.id, nextVersion, nextKey, fromB64(pub.public_key))),
  }));
  const recoveryField = recovery
    ? {
        epoch: recovery.target.epoch,
        ciphertext: await recoveryEnvelopeFor(recovery.viewerId, recovery.orgId, vault.id, nextVersion, nextKey, recovery.target),
      }
    : {};
  await api(`/api/v1/vaults/${vault.id}/rotation`, "POST", {
    expected_key_version: vault.key_version,
    items,
    envelopes,
    recovery: recoveryField,
  });
  return { vaultKey: nextKey, keyVersion: nextVersion };
}
