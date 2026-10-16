import { api } from "../api";
import type { PublicKey, VaultInfo } from "../types";
import {
  KDF_MEMLIMIT,
  KDF_OPSLIMIT,
  combineShares,
  decryptItem,
  deriveKek,
  encryptItem,
  fingerprint,
  fromB64,
  identityKeypair,
  openSealed,
  openVaultKey,
  passphraseKek,
  passwordRecord,
  randomBytes,
  readPassword,
  sealBytes,
  sealVaultKey,
  secretbox,
  secretboxOpen,
  sodiumReady,
  splitKey,
  toB64,
} from "./vault";
import sodium from "libsodium-wrappers-sumo";

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
  const privateKey = secretboxOpen({ nonce: fromB64(me.private_key_nonce), ciphertext: fromB64(me.private_key_ciphertext) }, kek);
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
  });
}

export async function ensureVault(name = "Services"): Promise<VaultInfo> {
  const listed = await api<{ vaults: VaultInfo[] }>("/api/v1/vaults");
  if (listed.vaults.length > 0) {
    return listed.vaults[0];
  }
  const created = await api<{ id: string; name: string; key_version: number }>("/api/v1/vaults", "POST", { name });
  return { id: created.id, name: created.name, key_version: created.key_version, rotation_required: false, role: "owner" };
}

export async function newVaultKey(): Promise<Uint8Array> {
  await sodiumReady();
  return randomBytes(32);
}

export type CustodianChoice = { user_id: string; fingerprint: string; public_key: string };

export async function enrollRecovery(first: CustodianChoice, second: CustodianChoice, vault: VaultInfo, vaultKey: Uint8Array) {
  await sodiumReady();
  const org = randomBytes(32);
  const { share1, share2 } = splitKey(org);
  const sealed1 = sealBytes(share1, fromB64(first.public_key));
  const sealed2 = sealBytes(share2, fromB64(second.public_key));
  await api("/api/v1/recovery", "POST", {
    custodians: [
      { user_id: first.user_id, share_index: 1, fingerprint: first.fingerprint, share_ciphertext: toB64(sealed1) },
      { user_id: second.user_id, share_index: 2, fingerprint: second.fingerprint, share_ciphertext: toB64(sealed2) },
    ],
  });
  const wrapped = secretbox(vaultKey, org);
  await api(`/api/v1/vaults/${vault.id}/recovery-envelope`, "POST", {
    nonce: toB64(wrapped.nonce),
    ciphertext: toB64(wrapped.ciphertext),
  });
  sodium.memzero(org);
  sodium.memzero(share1);
  sodium.memzero(share2);
}

export async function myShare(keys: HeldKeys): Promise<string> {
  await sodiumReady();
  const row = await api<{ share_ciphertext: string }>("/api/v1/recovery/share");
  const share = openSealed(fromB64(row.share_ciphertext), keys.publicKey, keys.privateKey);
  const text = toB64(share);
  sodium.memzero(share);
  return text;
}

export async function loadPasswords(vault: VaultInfo, vaultKey: Uint8Array): Promise<Record<string, string>> {
  await sodiumReady();
  const listed = await api<{ items: { id: string; key_version: number; nonce: string; ciphertext: string }[] }>(
    `/api/v1/vaults/${vault.id}/items`,
  );
  const out: Record<string, string> = {};
  for (const item of listed.items) {
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
  return out;
}

export async function savePassword(vault: VaultInfo, vaultKey: Uint8Array, accountId: string, itemId: string | null, password: string) {
  await sodiumReady();
  const id = itemId || crypto.randomUUID();
  const boxed = encryptItem(vault.id, id, vault.key_version, vaultKey, passwordRecord(password));
  const body = { id, nonce: toB64(boxed.nonce), ciphertext: toB64(boxed.ciphertext) };
  if (itemId) {
    await api(`/api/v1/vaults/${vault.id}/items/${id}`, "PUT", { nonce: body.nonce, ciphertext: body.ciphertext });
  } else {
    await api(`/api/v1/vaults/${vault.id}/items`, "POST", body);
    await api(`/api/v1/accounts/${accountId}/vault-link`, "POST", { vault_id: vault.id, vault_item_id: id });
  }
  return id;
}

export async function rotateVault(vault: VaultInfo, vaultKey: Uint8Array, share1: string, share2: string) {
  await sodiumReady();
  const org = combineShares(fromB64(share1), fromB64(share2));
  const nextKey = randomBytes(32);
  const nextVersion = vault.key_version + 1;
  const listed = await api<{ items: { id: string; key_version: number; nonce: string; ciphertext: string }[] }>(
    `/api/v1/vaults/${vault.id}/items`,
  );
  const items = listed.items.map((item) => {
    const plain = decryptItem(vault.id, item.id, item.key_version, vaultKey, {
      nonce: fromB64(item.nonce),
      ciphertext: fromB64(item.ciphertext),
    });
    const boxed = encryptItem(vault.id, item.id, nextVersion, nextKey, plain);
    return { id: item.id, nonce: toB64(boxed.nonce), ciphertext: toB64(boxed.ciphertext) };
  });
  const detail = await api<{ members: { user_id: string }[] }>(`/api/v1/vaults/${vault.id}`);
  const keysList = await api<{ keys: PublicKey[] }>("/api/v1/crypto/keys");
  const envelopes = detail.members.map((member) => {
    const pub = keysList.keys.find((row) => row.user_id === member.user_id && row.key_status === "approved");
    if (!pub) {
      throw new Error("fingerprint_mismatch");
    }
    return {
      user_id: member.user_id,
      fingerprint: pub.fingerprint,
      ciphertext: toB64(sealVaultKey(vault.id, nextVersion, nextKey, fromB64(pub.public_key))),
    };
  });
  const wrapped = secretbox(nextKey, org);
  await api(`/api/v1/vaults/${vault.id}/rotation`, "POST", {
    expected_key_version: vault.key_version,
    items,
    envelopes,
    recovery: { nonce: toB64(wrapped.nonce), ciphertext: toB64(wrapped.ciphertext) },
  });
  sodium.memzero(org);
  sodium.memzero(vaultKey);
  return { vaultKey: nextKey, keyVersion: nextVersion };
}
