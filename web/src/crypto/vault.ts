import sodium from "libsodium-wrappers-sumo";

export const KDF_OPSLIMIT = 3;
export const KDF_MEMLIMIT = 64 * 1024 * 1024;
export const KDF_ALGORITHM = "argon2id";

let readyPromise: Promise<void> | null = null;

export function sodiumReady(): Promise<void> {
  if (readyPromise) {
    return readyPromise;
  }
  readyPromise = sodium.ready;
  return sodium.ready;
}

export function toB64(raw: Uint8Array): string {
  return sodium.to_base64(raw, sodium.base64_variants.ORIGINAL);
}

export function fromB64(value: string): Uint8Array {
  return sodium.from_base64(value, sodium.base64_variants.ORIGINAL);
}

export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(publicKey));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function identityKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const pair = sodium.crypto_box_keypair();
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

export function randomBytes(n: number): Uint8Array {
  return sodium.randombytes_buf(n);
}

export function deriveKek(passphrase: string, salt: Uint8Array, opslimit: number, memlimit: number): Uint8Array {
  if (salt.length !== sodium.crypto_pwhash_SALTBYTES) {
    throw new Error("bad_salt");
  }
  return sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES,
    passphrase,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

export function passphraseKek(passphrase: string, salt: Uint8Array): Uint8Array {
  return deriveKek(passphrase, salt, KDF_OPSLIMIT, KDF_MEMLIMIT);
}

export type Boxed = { nonce: Uint8Array; ciphertext: Uint8Array };

export function secretbox(message: Uint8Array, key: Uint8Array): Boxed {
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = sodium.crypto_secretbox_easy(message, nonce, key);
  return { nonce, ciphertext };
}

export function secretboxOpen(boxed: Boxed, key: Uint8Array): Uint8Array {
  return sodium.crypto_secretbox_open_easy(boxed.ciphertext, boxed.nonce, key);
}

export function itemAAD(vaultId: string, itemId: string, keyVersion: number): Uint8Array {
  return sodium.from_string(`v1|${vaultId}|${itemId}|${keyVersion}`);
}

export function encryptItem(vaultId: string, itemId: string, keyVersion: number, vaultKey: Uint8Array, plaintext: string): Boxed {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    sodium.from_string(plaintext),
    itemAAD(vaultId, itemId, keyVersion),
    null,
    nonce,
    vaultKey,
  );
  return { nonce, ciphertext };
}

export function decryptItem(vaultId: string, itemId: string, keyVersion: number, vaultKey: Uint8Array, boxed: Boxed): string {
  const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    boxed.ciphertext,
    itemAAD(vaultId, itemId, keyVersion),
    boxed.nonce,
    vaultKey,
  );
  return sodium.to_string(plain);
}

export type EnvelopePayload = { v: 1; vault_id: string; key_version: number; key: string };

export function sealVaultKey(vaultId: string, keyVersion: number, vaultKey: Uint8Array, recipientPublic: Uint8Array): Uint8Array {
  const payload: EnvelopePayload = { v: 1, vault_id: vaultId, key_version: keyVersion, key: toB64(vaultKey) };
  return sodium.crypto_box_seal(sodium.from_string(JSON.stringify(payload)), recipientPublic);
}

export function openVaultKey(
  ciphertext: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  vaultId: string,
  keyVersion: number,
): Uint8Array {
  const plain = sodium.to_string(sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey));
  const parsed = JSON.parse(plain) as EnvelopePayload;
  if (parsed.v !== 1 || parsed.vault_id !== vaultId || parsed.key_version !== keyVersion) {
    throw new Error("envelope_mismatch");
  }
  const key = fromB64(parsed.key);
  if (key.length !== 32) {
    throw new Error("envelope_mismatch");
  }
  return key;
}

export function splitKey(secret: Uint8Array): { share1: Uint8Array; share2: Uint8Array } {
  if (secret.length !== 32) {
    throw new Error("bad_key");
  }
  const share1 = sodium.randombytes_buf(32);
  const share2 = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    share2[i] = secret[i] ^ share1[i];
  }
  return { share1, share2 };
}

export function combineShares(share1: Uint8Array, share2: Uint8Array): Uint8Array {
  if (share1.length !== 32 || share2.length !== 32) {
    throw new Error("bad_share");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = share1[i] ^ share2[i];
  }
  return out;
}

export function sealBytes(message: Uint8Array, recipientPublic: Uint8Array): Uint8Array {
  return sodium.crypto_box_seal(message, recipientPublic);
}

export function openSealed(ciphertext: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey);
}

export function passwordRecord(password: string): string {
  return JSON.stringify({ v: 1, password });
}

export function readPassword(plaintext: string): string {
  const parsed = JSON.parse(plaintext) as { v?: number; password?: string };
  if (parsed.v !== 1 || typeof parsed.password !== "string") {
    throw new Error("bad_item");
  }
  return parsed.password;
}
