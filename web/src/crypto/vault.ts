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

// Organization recovery, format 2 (docs/CRYPTO.md "Organization recovery").

export function recoveryKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  return identityKeypair();
}

// publicFromPrivate derives the X25519 public key, to check recombined shares.
export function publicFromPrivate(privateKey: Uint8Array): Uint8Array {
  return sodium.crypto_scalarmult_base(privateKey);
}

export type SharePayload = {
  v: 2;
  org_id: string;
  epoch: number;
  share_index: number;
  sender_user_id: string;
  sender_fingerprint: string;
  custodian_user_id: string;
  custodian_fingerprint: string;
  share: string;
  recovery_public_key: string;
};

// boxShare sends a share with crypto_box_easy: authenticated from the
// setting-up admin's identity key to the custodian's.
export function boxShare(payload: SharePayload, custodianPublic: Uint8Array, senderPrivate: Uint8Array): Boxed {
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const ciphertext = sodium.crypto_box_easy(sodium.from_string(JSON.stringify(payload)), nonce, custodianPublic, senderPrivate);
  return { nonce, ciphertext };
}

export function openShare(boxed: Boxed, senderPublic: Uint8Array, myPrivate: Uint8Array): SharePayload {
  const plain = sodium.crypto_box_open_easy(boxed.ciphertext, boxed.nonce, senderPublic, myPrivate);
  const parsed = JSON.parse(sodium.to_string(plain)) as SharePayload;
  sodium.memzero(plain);
  if (parsed.v !== 2 || fromB64(parsed.share).length !== 32 || fromB64(parsed.recovery_public_key).length !== 32) {
    throw new Error("share_mismatch");
  }
  return parsed;
}

export type RecoveryContext = { org_id: string; vault_id: string; key_version: number; epoch: number; recovery_fingerprint: string };

export function sealRecoveryEnvelope(context: RecoveryContext, vaultKey: Uint8Array, recoveryPublic: Uint8Array): Uint8Array {
  const payload = { v: 2, ...context, key: toB64(vaultKey) };
  return sodium.crypto_box_seal(sodium.from_string(JSON.stringify(payload)), recoveryPublic);
}

// openRecoveryEnvelope checks every context field; sealed boxes have no AD.
export function openRecoveryEnvelope(ciphertext: Uint8Array, recoveryPublic: Uint8Array, recoveryPrivate: Uint8Array, expect: RecoveryContext): Uint8Array {
  const plain = sodium.crypto_box_seal_open(ciphertext, recoveryPublic, recoveryPrivate);
  const parsed = JSON.parse(sodium.to_string(plain)) as RecoveryContext & { v: number; key: string };
  sodium.memzero(plain);
  const same = (Object.keys(expect) as (keyof RecoveryContext)[]).every((field) => parsed[field] === expect[field]);
  if (parsed.v !== 2 || !same) {
    throw new Error("envelope_mismatch");
  }
  const key = fromB64(parsed.key);
  if (key.length !== 32) {
    throw new Error("envelope_mismatch");
  }
  return key;
}

export function openSealed(ciphertext: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey);
}

// An account's vault item. Format 1 held only the password; format 2 adds
// custom fields and the documents attached to the account (docs/CRYPTO.md).
export type CustomField = { name: string; value: string };
export type FileRef = { id: string; name: string; type: string; size: number; key: string; added: string };
export type AccountRecord = { password: string; fields: CustomField[]; files: FileRef[] };

export const emptyRecord: AccountRecord = { password: "", fields: [], files: [] };

export function passwordRecord(password: string): string {
  return accountRecord({ ...emptyRecord, password });
}

export function accountRecord(record: AccountRecord): string {
  return JSON.stringify({ v: 2, password: record.password, fields: record.fields, files: record.files });
}

export function readRecord(plaintext: string): AccountRecord {
  const parsed = JSON.parse(plaintext) as { v?: number; password?: unknown; fields?: unknown; files?: unknown };
  if ((parsed.v !== 1 && parsed.v !== 2) || typeof parsed.password !== "string") {
    throw new Error("bad_item");
  }
  if (parsed.v === 1) {
    return { ...emptyRecord, password: parsed.password };
  }
  const fields = Array.isArray(parsed.fields) ? parsed.fields : [];
  const files = Array.isArray(parsed.files) ? parsed.files : [];
  const isField = (f: unknown): f is CustomField => typeof f === "object" && f !== null && typeof (f as CustomField).name === "string" && typeof (f as CustomField).value === "string";
  const isFile = (f: unknown): f is FileRef => {
    const r = f as FileRef;
    return typeof f === "object" && f !== null && typeof r.id === "string" && typeof r.name === "string" && typeof r.type === "string" && typeof r.size === "number" && typeof r.key === "string" && typeof r.added === "string";
  };
  if (!fields.every(isField) || !files.every(isFile)) {
    throw new Error("bad_item");
  }
  return {
    password: parsed.password,
    fields: fields.map(({ name, value }) => ({ name, value })),
    files: files.map(({ id, name, type, size, key, added }) => ({ id, name, type, size, key, added })),
  };
}

export function readPassword(plaintext: string): string {
  return readRecord(plaintext).password;
}

// Documents use a fresh key each, so the vault key never encrypts bulk data
// and rotation only has to rewrap the small item that holds the file keys.
export function fileAAD(vaultId: string, fileId: string): Uint8Array {
  return sodium.from_string(`file|v1|${vaultId}|${fileId}`);
}

export function encryptFile(vaultId: string, fileId: string, fileKey: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, fileAAD(vaultId, fileId), null, nonce, fileKey);
  const out = new Uint8Array(nonce.length + ciphertext.length);
  out.set(nonce);
  out.set(ciphertext, nonce.length);
  return out;
}

export function decryptFile(vaultId: string, fileId: string, fileKey: Uint8Array, blob: Uint8Array): Uint8Array {
  const size = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, blob.subarray(size), fileAAD(vaultId, fileId), blob.subarray(0, size), fileKey);
}
