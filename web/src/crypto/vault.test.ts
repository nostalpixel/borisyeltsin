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
  openSealed,
  openVaultKey,
  passphraseKek,
  passwordRecord,
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

  it("combines a 2-of-2 XOR split and seals each share", () => {
    const org = sodium.randombytes_buf(32);
    const { share1, share2 } = splitKey(org);
    expect(toB64(combineShares(share1, share2))).toBe(toB64(org));
    const a = identityKeypair();
    const b = identityKeypair();
    const sealed1 = sealBytes(share1, a.publicKey);
    const sealed2 = sealBytes(share2, b.publicKey);
    const opened1 = openSealed(sealed1, a.publicKey, a.privateKey);
    const opened2 = openSealed(sealed2, b.publicKey, b.privateKey);
    expect(toB64(combineShares(opened1, opened2))).toBe(toB64(org));
    expect(() => openSealed(sealed1, b.publicKey, b.privateKey)).toThrow();
    expect(fromB64(toB64(org)).length).toBe(32);
  });
});
