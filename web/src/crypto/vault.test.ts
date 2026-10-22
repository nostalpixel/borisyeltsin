import { beforeAll, describe, expect, it } from "vitest";
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
  boxShare,
  openRecoveryEnvelope,
  openSealed,
  openShare,
  openVaultKey,
  passphraseKek,
  accountRecord,
  decryptFile,
  encryptFile,
  passwordRecord,
  publicFromPrivate,
  readPassword,
  readRecord,
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

beforeAll(async () => {
  await sodiumReady();
});

describe("vault crypto", () => {
  it("locks the production Argon2id floor", () => {
    expect(KDF_OPSLIMIT).toBe(3);
    expect(KDF_MEMLIMIT).toBe(67108864);
    expect(KDF_OPSLIMIT).toBeGreaterThanOrEqual(sodium.crypto_pwhash_OPSLIMIT_MIN);
    expect(KDF_MEMLIMIT).toBeGreaterThanOrEqual(sodium.crypto_pwhash_MEMLIMIT_MIN);
  });

  it("round-trips a secretbox under minimum KDF limits", () => {
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const kek = deriveKek("correct horse", salt, sodium.crypto_pwhash_OPSLIMIT_MIN, sodium.crypto_pwhash_MEMLIMIT_MIN);
    const message = sodium.from_string("private-key");
    const boxed = secretbox(message, kek);
    expect(sodium.to_string(secretboxOpen(boxed, kek))).toBe("private-key");
    expect(boxed.nonce.length).toBe(24);
  });

  it("opens a private-key backup with a 32-byte recovery key", () => {
    const pair = identityKeypair();
    const recovery = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
    const boxed = secretbox(pair.privateKey, recovery);
    expect(toB64(secretboxOpen(boxed, recovery))).toBe(toB64(pair.privateKey));
    expect(() => secretboxOpen(boxed, sodium.randombytes_buf(32))).toThrow();
  });

  it("round-trips the production passphrase KEK once", () => {
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const kek = passphraseKek("production-passphrase", salt);
    const boxed = secretbox(sodium.from_string("identity"), kek);
    expect(sodium.to_string(secretboxOpen(boxed, kek))).toBe("identity");
    expect(kek.length).toBe(32);
  });

  it("seals a vault key and rejects a vault mismatch", () => {
    const owner = identityKeypair();
    const vaultKey = sodium.randombytes_buf(32);
    const sealed = sealVaultKey("vault-1", 1, vaultKey, owner.publicKey);
    const opened = openVaultKey(sealed, owner.publicKey, owner.privateKey, "vault-1", 1);
    expect(toB64(opened)).toBe(toB64(vaultKey));
    expect(() => openVaultKey(sealed, owner.publicKey, owner.privateKey, "vault-2", 1)).toThrow("envelope_mismatch");
    expect(() => openVaultKey(sealed, owner.publicKey, owner.privateKey, "vault-1", 2)).toThrow("envelope_mismatch");
  });

  it("encrypts an item with the documented AAD", async () => {
    const key = sodium.randombytes_buf(32);
    const boxed = encryptItem("vault", "item", 3, key, passwordRecord("hunter2"));
    expect(readPassword(decryptItem("vault", "item", 3, key, boxed))).toBe("hunter2");
    expect(() => decryptItem("vault", "other", 3, key, boxed)).toThrow();
    await expect(fingerprint(identityKeypair().publicKey)).resolves.toMatch(/^[0-9a-f]{64}$/);
  });

  it("splits a recovery private key, recombines it and checks the public key", () => {
    const recovery = recoveryKeypair();
    const { share1, share2 } = splitKey(recovery.privateKey);
    const joined = combineShares(share1, share2);
    expect(toB64(publicFromPrivate(joined))).toBe(toB64(recovery.publicKey));
    // Byte 0's low 3 bits are clamped away by X25519, so flip a bit that counts.
    share2[5] ^= 1;
    expect(toB64(publicFromPrivate(combineShares(share1, share2)))).not.toBe(toB64(recovery.publicKey));
  });

  it("opens a custodian share only from the expected sender", () => {
    const admin = identityKeypair();
    const custodian = identityKeypair();
    const stranger = identityKeypair();
    const recovery = recoveryKeypair();
    const payload: SharePayload = {
      v: 2,
      org_id: "org",
      epoch: 1,
      share_index: 1,
      sender_user_id: "admin",
      sender_fingerprint: "a",
      custodian_user_id: "c",
      custodian_fingerprint: "c",
      share: toB64(sodium.randombytes_buf(32)),
      recovery_public_key: toB64(recovery.publicKey),
    };
    const boxed = boxShare(payload, custodian.publicKey, admin.privateKey);
    expect(openShare(boxed, admin.publicKey, custodian.privateKey)).toEqual(payload);
    // A box from anyone but the pinned sender does not open.
    const forged = boxShare(payload, custodian.publicKey, stranger.privateKey);
    expect(() => openShare(forged, admin.publicKey, custodian.privateKey)).toThrow();
  });

  it("opens a recovery envelope with the recombined key and checks its context", () => {
    const recovery = recoveryKeypair();
    const vaultKey = sodium.randombytes_buf(32);
    const context = { org_id: "org", vault_id: "vault", key_version: 3, epoch: 2, recovery_fingerprint: "ff" };
    const sealed = sealRecoveryEnvelope(context, vaultKey, recovery.publicKey);
    const { share1, share2 } = splitKey(recovery.privateKey);
    const joined = combineShares(share1, share2);
    expect(toB64(openRecoveryEnvelope(sealed, recovery.publicKey, joined, context))).toBe(toB64(vaultKey));
    expect(() => openRecoveryEnvelope(sealed, recovery.publicKey, joined, { ...context, epoch: 1 })).toThrow("envelope_mismatch");
    expect(() => openRecoveryEnvelope(sealed, recovery.publicKey, joined, { ...context, org_id: "other" })).toThrow("envelope_mismatch");
  });

  it("opens a box sealed by the Go server (nacl/box.SealAnonymous)", () => {
    // Key pair and Go-sealed box from internal/httpserver/recovery_test.go.
    const publicKey = fromB64("iljxAgbEX8kwDZbw9YWYBO9QckcDAjDA7iEsWPIStlk=");
    const privateKey = fromB64("q/HDD5h1F1Q0Lpm1sjV6bvibyh4+Wuw1jn8JhTYemnI=");
    const sealed = fromB64("D+RBPnCigWW1/7iZRWlHjHHi97psfiGWUpv1v6QGTibYYyeEjxsmw9ddzvutX+/7+sAVoY3Gkqj30695CO5Y8OsoWiRBJm0w9UMlNwA=");
    expect(sodium.to_string(openSealed(sealed, publicKey, privateKey))).toBe("borisyeltsin challenge vector");
  });
});

describe("account records and documents", () => {
  it("reads format 1 items as a password with no extras", () => {
    expect(readRecord(JSON.stringify({ v: 1, password: "old" }))).toEqual({ password: "old", fields: [], files: [] });
  });

  it("round-trips format 2 and drops unknown keys", () => {
    const record = {
      password: "p",
      fields: [{ name: "Account ID", value: "A-42" }],
      files: [{ id: "f1", name: "contract.pdf", type: "application/pdf", size: 3, key: "k", added: "2026-10-22T00:00:00Z" }],
    };
    const raw = JSON.parse(accountRecord(record));
    expect(raw.v).toBe(2);
    raw.fields[0].extra = "x";
    expect(readRecord(JSON.stringify(raw))).toEqual(record);
    expect(readPassword(passwordRecord("hunter2"))).toBe("hunter2");
  });

  it("refuses malformed records", () => {
    expect(() => readRecord(JSON.stringify({ v: 3, password: "" }))).toThrow("bad_item");
    expect(() => readRecord(JSON.stringify({ v: 2, password: "", fields: [{ name: 1, value: "" }] }))).toThrow("bad_item");
    expect(() => readRecord(JSON.stringify({ v: 2, password: "", files: [{ id: "f" }] }))).toThrow("bad_item");
  });

  it("encrypts each document under its own key, bound to vault and file id", () => {
    const key = sodium.randombytes_buf(32);
    const plain = new TextEncoder().encode("%PDF-1.7 contract");
    const sealed = encryptFile("vault", "file", key, plain);
    expect(sealed.length).toBe(plain.length + 24 + 16);
    expect(decryptFile("vault", "file", key, sealed)).toEqual(plain);
    expect(() => decryptFile("vault", "other-file", key, sealed)).toThrow();
    expect(() => decryptFile("other-vault", "file", key, sealed)).toThrow();
    expect(() => decryptFile("vault", "file", sodium.randombytes_buf(32), sealed)).toThrow();
    const tampered = sealed.slice();
    tampered[30] ^= 1;
    expect(() => decryptFile("vault", "file", key, tampered)).toThrow();
  });
});
