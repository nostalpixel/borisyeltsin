import { useEffect, useState } from "react";
import { ApiError, api, explain } from "./api";
import { pinKey, pinState } from "./crypto/pins";
import {
  changePassphrase,
  enrollRecovery,
  ensureVault,
  loadPasswords,
  myShare,
  newVaultKey,
  readVaultKey,
  rotateVault,
  shareVaultKey,
  unlockIdentity,
  unlockWithRecoveryKey,
  writeOwnerEnvelope,
  type HeldKeys,
} from "./crypto/session";
import type { PublicKey, VaultInfo } from "./types";
import { StatusLine } from "./workspace";
import { Fingerprint, PinBadge, VerifyKeyDialog } from "./verify";

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

type Tab = "items" | "members" | "recovery";

type Member = { user_id: string; role: string; display_name: string; email: string; has_key: boolean };

// Verify describes a pending verify-key dialog and what happens after it.
type Verify = { key: PublicKey; label?: string; then?: () => Promise<void> };

export function VaultPage({ userId, recoveryReady, open, onOpen, onChanged }: Props) {
  const [tab, setTab] = useState<Tab>("items");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [keys, setKeys] = useState<PublicKey[]>([]);
  const [verify, setVerify] = useState<Verify | null>(null);
  const [, setPinsChanged] = useState(0);

  useEffect(() => {
    api<{ keys: PublicKey[] }>("/api/v1/crypto/keys")
      .then((row) => setKeys(row.keys.filter((item) => item.key_status === "approved" && item.user_status === "active")))
      .catch((err) => setError(explain(err)));
  }, [recoveryReady, open?.vault.key_version]);

  async function run(action: () => Promise<void>) {
    setError("");
    try {
      await action();
    } catch (err) {
      setError(explain(err));
    }
  }

  // withVerified runs action once the key is pinned, asking first if needed.
  function withVerified(key: PublicKey, action: () => Promise<void>, label?: string) {
    if (pinState(userId, key.user_id, key.fingerprint).state === "verified") {
      run(action);
      return;
    }
    setVerify({ key, label, then: action });
  }

  if (!open) {
    return (
      <div className="content">
        <h1>Vault</h1>
        <p className="intro">Passwords are encrypted in this browser. The server stores only encrypted copies and cannot open them.</p>
        <UnlockPanel
          userId={userId}
          recoveryReady={recoveryReady}
          onOpen={(next) => {
            onOpen(next);
            setNotice(recoveryReady ? "vault unlocked" : "unlocked; set up recovery before saving passwords");
            setTab(recoveryReady ? "items" : "recovery");
          }}
        />
      </div>
    );
  }

  const isKeyOwner = open.vault.role === "owner";
  const stored = Object.keys(open.passwords).length;
  return (
    <div className="content">
      <div className="heading">
        <div>
          <h1>{open.vault.name}</h1>
          <p className="stat-strip">
            {`key v${open.vault.key_version}  ·  ${stored} passwords  ·  recovery ${recoveryReady ? "ready" : "not set up"}`}
          </p>
        </div>
        <button
          className="btn"
          onClick={() => {
            onOpen(null);
            setNotice("vault locked in this tab");
          }}
        >
          Lock vault
        </button>
      </div>
      {open.vault.rotation_required && (
        <div className="banner">Someone left the vault or replaced their key. An owner should rotate the vault key in Recovery.</div>
      )}
      {error && <div className="banner bad">{error}</div>}
      <div className="tabs" role="tablist" aria-label="Vault">
        {(
          [
            ["items", "Items"],
            ["members", "Members"],
            ["recovery", "Recovery"],
          ] as [Tab, string][]
        ).map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "tab active" : "tab"} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      <section role="tabpanel">
        {tab === "items" && (
          <div className="panel">
            {stored === 0 ? (
              <p className="empty-state">
                No passwords yet. Open a service on the Services page and type a password into one of its accounts.
                {isKeyOwner && " Then share the vault with a teammate from Members."}
              </p>
            ) : (
              <p className="prose">
                {stored} passwords are stored in this vault. You see and edit them next to their accounts on the Services page.
              </p>
            )}
          </div>
        )}
        {tab === "members" && (
          <MembersTab
            userId={userId}
            open={open}
            keys={keys}
            canManage={isKeyOwner}
            run={run}
            withVerified={withVerified}
            onVerify={(key) => setVerify({ key })}
            setNotice={setNotice}
          />
        )}
        {tab === "recovery" && (
          <RecoveryTab
            userId={userId}
            open={open}
            keys={keys}
            recoveryReady={recoveryReady}
            canRotate={isKeyOwner}
            run={run}
            onVerify={(key) => setVerify({ key })}
            onOpen={onOpen}
            onChanged={onChanged}
            setNotice={setNotice}
          />
        )}
      </section>
      <footer className="bottom">
        <span />
        <StatusLine text={notice || "the server never sees your passphrase"} />
      </footer>
      {verify && (
        <VerifyKeyDialog
          viewerId={userId}
          userId={verify.key.user_id}
          name={verify.key.display_name || verify.key.email}
          fingerprint={verify.key.fingerprint}
          confirmLabel={verify.label}
          onConfirm={async () => {
            pinKey(userId, verify.key.user_id, verify.key.fingerprint);
            setPinsChanged((n) => n + 1);
            if (verify.then) await verify.then();
          }}
          onClose={() => setVerify(null)}
        />
      )}
    </div>
  );
}

function UnlockPanel({ userId, recoveryReady, onOpen }: { userId: string; recoveryReady: boolean; onOpen: (next: OpenVault) => void }) {
  const [passphrase, setPassphrase] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function finishUnlock(held: HeldKeys) {
    // The browser just checked this key against the approved fingerprint.
    pinKey(userId, userId, held.fingerprint);
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
      vault.initialized = true;
    }
    const items = recoveryReady ? await loadPasswords(vault, vaultKey) : { passwords: {}, versions: {} };
    onOpen({ keys: held, vault, vaultKey, ...items });
  }

  return (
    <form
      className="auth-card"
      onSubmit={(event) => {
        event.preventDefault();
        const phrase = passphrase;
        const savedRecovery = recoveryKey.replace(/\s+/g, "");
        setPassphrase("");
        setRecoveryKey("");
        setBusy(true);
        setError("");
        (async () => {
          const held = useRecovery ? await unlockWithRecoveryKey(savedRecovery) : await unlockIdentity(phrase);
          await finishUnlock(held);
        })()
          .catch((err) => setError(explain(err)))
          .finally(() => setBusy(false));
      }}
    >
      {error && <div className="banner bad">{error}</div>}
      {useRecovery ? (
        <label className="field">
          <span>Recovery key</span>
          <textarea value={recoveryKey} onChange={(event) => setRecoveryKey(event.target.value)} rows={3} autoComplete="off" spellCheck={false} required />
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
  );
}

type MembersProps = {
  userId: string;
  open: OpenVault;
  keys: PublicKey[];
  canManage: boolean;
  run: (action: () => Promise<void>) => Promise<void>;
  withVerified: (key: PublicKey, action: () => Promise<void>, label?: string) => void;
  onVerify: (key: PublicKey) => void;
  setNotice: (text: string) => void;
};

function MembersTab({ userId, open, keys, canManage, run, withVerified, onVerify, setNotice }: MembersProps) {
  const [members, setMembers] = useState<Member[]>([]);
  const [loadError, setLoadError] = useState("");
  const [adding, setAdding] = useState("");
  const [role, setRole] = useState("member");

  async function reload() {
    const detail = await api<{ members: Member[] }>(`/api/v1/vaults/${open.vault.id}`);
    setMembers(detail.members);
  }

  useEffect(() => {
    reload().catch((err) => setLoadError(explain(err)));
  }, [open.vault.id, open.vault.key_version]);

  const keyOf = (id: string) => keys.find((key) => key.user_id === id);
  const memberIds = new Set(members.map((member) => member.user_id));
  const candidates = keys.filter((key) => !memberIds.has(key.user_id));

  function share(member: Member) {
    const key = keyOf(member.user_id);
    if (!key) return;
    withVerified(
      key,
      async () => {
        await shareVaultKey(userId, open.vault, open.vaultKey, key);
        await reload();
        setNotice(`vault key shared with ${member.display_name || member.email}`);
      },
      "Fingerprints match, share",
    );
  }

  if (loadError) {
    return (
      <div className="banner bad">
        {loadError}{" "}
        <button className="text-button" onClick={() => reload().then(() => setLoadError(""), (err) => setLoadError(explain(err)))}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <>
      <div className="data-table">
        <div className="data-head" aria-hidden="true">
          <span>Member</span>
          <span>Role</span>
          <span>Key</span>
          <span />
        </div>
        {members.length === 1 && <p className="empty-state">Only you so far.{canManage && " Add a teammate below, then share the key."}</p>}
        {members.map((member) => {
          const key = keyOf(member.user_id);
          const self = member.user_id === userId;
          return (
            <div key={member.user_id} className="data-row">
              <span>
                <span className="service-name">{member.display_name || member.email}</span>
                <span className="service-sub">{member.email}</span>
              </span>
              <span>{member.role}</span>
              <span>
                {member.has_key ? "has key" : <span className="warn-text">● no key yet</span>}
                <br />
                {key && !self && <PinBadge viewerId={userId} userId={member.user_id} fingerprint={key.fingerprint} />}
                {self && <span className="ok-text">✓ you</span>}
              </span>
              <span className="row-actions">
                {key && !self && pinState(userId, key.user_id, key.fingerprint).state !== "verified" && (
                  <button className="btn subtle" onClick={() => onVerify(key)}>
                    Verify
                  </button>
                )}
                {canManage && !member.has_key && key && (
                  <button className="btn" onClick={() => share(member)}>
                    Share key
                  </button>
                )}
                {canManage && !self && (
                  <button
                    className="btn subtle danger"
                    onClick={() =>
                      run(async () => {
                        await api(`/api/v1/vaults/${open.vault.id}/members/${member.user_id}`, "DELETE");
                        await reload();
                        setNotice(`${member.email} removed; rotate the key and change shared passwords`);
                      })
                    }
                  >
                    Remove
                  </button>
                )}
              </span>
            </div>
          );
        })}
      </div>
      {canManage && (
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            const key = keyOf(adding);
            if (!key) return;
            run(async () => {
              await api(`/api/v1/vaults/${open.vault.id}/members`, "POST", { user_id: key.user_id, role });
              await reload();
              setAdding("");
              share({ user_id: key.user_id, role, display_name: key.display_name, email: key.email, has_key: false });
            });
          }}
        >
          <label className="field">
            <span>Add a teammate</span>
            <select value={adding} onChange={(event) => setAdding(event.target.value)} required>
              <option value="">{candidates.length === 0 ? "Everyone with an approved key is a member" : "Choose a person"}</option>
              {candidates.map((key) => (
                <option key={key.user_id} value={key.user_id}>
                  {key.display_name || key.email} · {key.email}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Role</span>
            <select value={role} onChange={(event) => setRole(event.target.value)}>
              <option value="member">Member (read)</option>
              <option value="manager">Manager (read and write)</option>
              <option value="owner">Owner (also shares and rotates)</option>
            </select>
          </label>
          <button className="btn primary" disabled={!adding}>
            Add and share
          </button>
        </form>
      )}
      {!canManage && <p className="modal-hint">Only vault owners who hold the key can add people or share it.</p>}
    </>
  );
}

type RecoveryProps = {
  userId: string;
  open: OpenVault;
  keys: PublicKey[];
  recoveryReady: boolean;
  canRotate: boolean;
  run: (action: () => Promise<void>) => Promise<void>;
  onVerify: (key: PublicKey) => void;
  onOpen: (next: OpenVault | null) => void;
  onChanged: () => Promise<void>;
  setNotice: (text: string) => void;
};

function RecoveryTab({ userId, open, keys, recoveryReady, canRotate, run, onVerify, onOpen, onChanged, setNotice }: RecoveryProps) {
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const [shareText, setShareText] = useState("");
  const [share1, setShare1] = useState("");
  const [share2, setShare2] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [again, setAgain] = useState("");
  const [formError, setFormError] = useState("");

  // Share text lives only in this component; locking the vault unmounts it.

  const verified = (id: string) => {
    const key = keys.find((item) => item.user_id === id);
    return key ? pinState(userId, key.user_id, key.fingerprint).state === "verified" : false;
  };

  return (
    <div className="stack wide">
      {!recoveryReady && (
        <form
          className="panel stack"
          onSubmit={(event) => {
            event.preventDefault();
            const a = keys.find((item) => item.user_id === first);
            const b = keys.find((item) => item.user_id === second);
            if (!a || !b || a.user_id === b.user_id) {
              setFormError("Choose two different people with approved keys.");
              return;
            }
            setFormError("");
            run(async () => {
              await enrollRecovery(userId, a, b, open.vault, open.vaultKey);
              setNotice("recovery set up; passwords can be saved");
              await onChanged();
            });
          }}
        >
          <h2>Set up recovery</h2>
          <p className="prose">
            Two custodians each hold one share. Together they can recover the vault key if every member loses access. One share alone cannot. Verify both
            custodians' keys first.
          </p>
          {(["Custodian 1", "Custodian 2"] as const).map((label, index) => {
            const value = index === 0 ? first : second;
            const key = keys.find((item) => item.user_id === value);
            return (
              <div key={label} className="stack">
                <label className="field">
                  <span>{label}</span>
                  <select value={value} onChange={(event) => (index === 0 ? setFirst : setSecond)(event.target.value)} required>
                    <option value="">Choose</option>
                    {keys.map((item) => (
                      <option key={item.user_id} value={item.user_id}>
                        {item.display_name || item.email} · {item.email}
                      </option>
                    ))}
                  </select>
                </label>
                {key && (
                  <span>
                    <PinBadge viewerId={userId} userId={key.user_id} fingerprint={key.fingerprint} />{" "}
                    {!verified(key.user_id) && (
                      <button type="button" className="text-button" onClick={() => onVerify(key)}>
                        Verify
                      </button>
                    )}
                  </span>
                )}
              </div>
            );
          })}
          {formError && <p className="import-error">{formError}</p>}
          <button className="btn primary" disabled={keys.length < 2 || !first || !second || !verified(first) || !verified(second)}>
            {keys.length < 2 ? "A second person with an approved key is needed" : "Seal the two shares"}
          </button>
        </form>
      )}

      {recoveryReady && (
        <div className="panel stack">
          <h2>Your recovery share</h2>
          <p className="prose">Reveal your share only while you and the other custodian are recovering the vault together.</p>
          {shareText ? (
            <>
              <Fingerprint value={shareText} label="Your share" />
              <button className="btn" onClick={() => setShareText("")}>
                Hide share
              </button>
            </>
          ) : (
            <button className="btn" onClick={() => run(async () => setShareText(await myShare(open.keys)))}>
              Show my share
            </button>
          )}
        </div>
      )}

      {recoveryReady && canRotate && (
        <form
          className="panel stack"
          onSubmit={(event) => {
            event.preventDefault();
            run(async () => {
              const next = await rotateVault(userId, open.vault, open.vaultKey, share1.replace(/\s+/g, ""), share2.replace(/\s+/g, ""));
              const items = await loadPasswords({ ...open.vault, key_version: next.keyVersion }, next.vaultKey);
              onOpen({ ...open, vault: { ...open.vault, key_version: next.keyVersion, rotation_required: false }, vaultKey: next.vaultKey, ...items });
              setShare1("");
              setShare2("");
              setNotice("vault key rotated; old envelopes deleted");
              await onChanged();
            });
          }}
        >
          <h2>Rotate the vault key</h2>
          <p className="prose">
            Rotate after someone leaves. Every member's key must be verified in this browser first. Both shares re-seal the new key; old shares stay valid
            until the custodians set up recovery again.
          </p>
          <label className="field">
            <span>Share 1</span>
            <textarea value={share1} onChange={(event) => setShare1(event.target.value)} rows={2} spellCheck={false} autoComplete="off" />
          </label>
          <label className="field">
            <span>Share 2</span>
            <textarea value={share2} onChange={(event) => setShare2(event.target.value)} rows={2} spellCheck={false} autoComplete="off" />
          </label>
          <button className="btn primary" disabled={!share1 || !share2}>
            Rotate key
          </button>
        </form>
      )}

      <form
        className="panel stack"
        onSubmit={(event) => {
          event.preventDefault();
          if (passphrase.length < 12) {
            setFormError("The new passphrase must be at least 12 characters.");
            return;
          }
          if (passphrase !== again) {
            setFormError("The new passphrases do not match.");
            return;
          }
          setFormError("");
          const next = passphrase;
          setPassphrase("");
          setAgain("");
          run(async () => {
            await changePassphrase(open.keys, next);
            setNotice("passphrase changed; your recovery key still works");
          });
        }}
      >
        <h2>Change your passphrase</h2>
        <p className="prose">Your key stays the same, so nothing needs to be shared again. Your recovery key keeps working.</p>
        <label className="field">
          <span>New passphrase</span>
          <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete="new-password" required />
        </label>
        <label className="field">
          <span>Repeat</span>
          <input type="password" value={again} onChange={(event) => setAgain(event.target.value)} autoComplete="new-password" required />
        </label>
        <button className="btn primary">Change passphrase</button>
      </form>
    </div>
  );
}
