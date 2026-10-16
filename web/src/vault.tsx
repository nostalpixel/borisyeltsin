import { useEffect, useState } from "react";
import { ApiError, api, explain } from "./api";
import {
  enrollRecovery,
  ensureVault,
  loadPasswords,
  myShare,
  newVaultKey,
  readVaultKey,
  rotateVault,
  unlockIdentity,
  unlockWithRecoveryKey,
  writeOwnerEnvelope,
  type HeldKeys,
} from "./crypto/session";
import type { PublicKey, VaultInfo } from "./types";

export type OpenVault = {
  keys: HeldKeys;
  vault: VaultInfo;
  vaultKey: Uint8Array;
  passwords: Record<string, string>;
  versions: Record<string, number>;
};

type Props = {
  userId: string;
  recoveryReady: boolean;
  open: OpenVault | null;
  onOpen: (next: OpenVault | null) => void;
  onChanged: () => Promise<void>;
};

export function VaultPage({ userId, recoveryReady, open, onOpen, onChanged }: Props) {
  const [passphrase, setPassphrase] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [keys, setKeys] = useState<PublicKey[]>([]);
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const [shareText, setShareText] = useState("");
  const [share1, setShare1] = useState("");
  const [share2, setShare2] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ keys: PublicKey[] }>("/api/v1/crypto/keys")
      .then((row) => setKeys(row.keys.filter((item) => item.key_status === "approved" && item.user_status === "active")))
      .catch(() => setKeys([]));
  }, [recoveryReady]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (err) {
      setError(explain(err));
    } finally {
      setBusy(false);
    }
  }

  async function finishUnlock(held: HeldKeys) {
    const vault = await ensureVault();
    let vaultKey: Uint8Array;
    try {
      vaultKey = await readVaultKey(held, vault.id, vault.key_version);
    } catch (err) {
      // A new key is minted only for a vault that never had one. Anywhere
      // else a missing envelope means "not shared with you yet".
      if (!(err instanceof ApiError) || err.status !== 404 || vault.initialized || vault.role !== "owner") throw err;
      vaultKey = await newVaultKey();
      await writeOwnerEnvelope(held, userId, vault.id, vault.key_version, vaultKey);
    }
    const items = recoveryReady ? await loadPasswords(vault, vaultKey) : { passwords: {}, versions: {} };
    onOpen({ keys: held, vault, vaultKey, ...items });
    setNotice(recoveryReady ? "Vault unlocked." : "Personal key unlocked. Assign two custodians before saving passwords.");
  }

  return (
    <div className="content">
      <p className="eyebrow">Vault</p>
      <h1>Team keys</h1>
      <p className="intro">The server stores only encrypted envelopes. Your passphrase and private key never leave this browser.</p>
      {error && <div className="banner bad">{error}</div>}
      {notice && <p className="modal-hint">{notice}</p>}
      {!open && (
        <form
          className="auth-card grid gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            const phrase = passphrase;
            const savedRecovery = recoveryKey;
            setPassphrase("");
            setRecoveryKey("");
            run(async () => {
              const held = useRecovery ? await unlockWithRecoveryKey(savedRecovery) : await unlockIdentity(phrase);
              await finishUnlock(held);
            });
          }}
        >
          {useRecovery ? (
            <label className="field">
              <span>Recovery key</span>
              <textarea value={recoveryKey} onChange={(event) => setRecoveryKey(event.target.value)} rows={3} autoComplete="off" required />
            </label>
          ) : (
            <label className="field">
              <span>Passphrase</span>
              <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete="current-password" required />
            </label>
          )}
          <button className="btn primary" disabled={busy}>
            {busy ? "Unlocking…" : "Unlock vault"}
          </button>
          <button
            className="btn"
            type="button"
            onClick={() => {
              setUseRecovery((current) => !current);
              setError("");
            }}
          >
            {useRecovery ? "Unlock with passphrase" : "Unlock with recovery key"}
          </button>
          {useRecovery && <p className="modal-hint">An Authentik password reset does not replace this key. It was shown once, when you created your key.</p>}
        </form>
      )}
      {open && (
        <div className="grid gap-4">
          <p className="modal-hint">
            Vault "{open.vault.name}", key version {open.vault.key_version}. {recoveryReady ? "Recovery is ready." : "Recovery is not set up yet."}
            {open.vault.rotation_required ? " Key rotation needed: a member's public key changed." : ""}
          </p>
          {!recoveryReady && (
            <form
              className="auth-card grid gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                const a = keys.find((item) => item.user_id === first);
                const b = keys.find((item) => item.user_id === second);
                if (!a || !b) {
                  setError("Choose two different members with approved keys.");
                  return;
                }
                run(async () => {
                  await enrollRecovery(a, b, open.vault, open.vaultKey);
                  setNotice("Both recovery shares are sealed. You can save passwords now.");
                  await onChanged();
                });
              }}
            >
              <h2>Two custodians</h2>
              <p className="modal-hint">Each gets one share. Together they can recover the vault key. One share alone cannot.</p>
              <label className="field">
                <span>Custodian 1</span>
                <select value={first} onChange={(event) => setFirst(event.target.value)} required>
                  <option value="">Choose</option>
                  {keys.map((item) => (
                    <option key={item.user_id} value={item.user_id}>
                      {item.display_name} · {item.email}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Custodian 2</span>
                <select value={second} onChange={(event) => setSecond(event.target.value)} required>
                  <option value="">Choose</option>
                  {keys.map((item) => (
                    <option key={item.user_id} value={item.user_id}>
                      {item.display_name} · {item.email}
                    </option>
                  ))}
                </select>
              </label>
              <button className="btn primary" disabled={busy || keys.length < 2}>
                {keys.length < 2 ? "A second member with a key is needed" : "Assign custodians"}
              </button>
            </form>
          )}
          <div className="flex gap-2">
            <button
              className="btn"
              onClick={() =>
                run(async () => {
                  setShareText(await myShare(open.keys));
                })
              }
            >
              Show my share
            </button>
            <button
              className="btn danger"
              onClick={() => {
                onOpen(null);
                setShareText("");
                setNotice("Vault locked in this tab.");
              }}
            >
              Lock vault
            </button>
          </div>
          {shareText && (
            <div>
              <p className="modal-hint">This is a secret. Give it to the other custodian only while you are recovering the vault together.</p>
              <p className="secret-once">{shareText}</p>
            </div>
          )}
          <form
            className="auth-card grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              run(async () => {
                const next = await rotateVault(open.vault, open.vaultKey, share1.trim(), share2.trim());
                const items = await loadPasswords({ ...open.vault, key_version: next.keyVersion }, next.vaultKey);
                onOpen({ ...open, vault: { ...open.vault, key_version: next.keyVersion, rotation_required: false }, vaultKey: next.vaultKey, ...items });
                setShare1("");
                setShare2("");
                setNotice("Vault key rotated. Old envelopes were deleted.");
                await onChanged();
              });
            }}
          >
            <h2>Rotate the vault key</h2>
            <p className="modal-hint">Both recovery shares are needed. They re-seal the new key and are never sent in the clear.</p>
            <label className="field">
              <span>Share 1</span>
              <textarea value={share1} onChange={(event) => setShare1(event.target.value)} rows={3} />
            </label>
            <label className="field">
              <span>Share 2</span>
              <textarea value={share2} onChange={(event) => setShare2(event.target.value)} rows={3} />
            </label>
            <button className="btn primary" disabled={busy}>
              Rotate key
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
