import { useEffect, useState } from "react";
import { ApiError, api, explain } from "./api";
import { pinKey, pinRecoveryKey, pinState, recoveryPinState, type PinState, type RecoveryPinState } from "./crypto/pins";
import {
  changePassphrase,
  confirmMyShare,
  ensureVault,
  finishRecovery,
  loadPasswords,
  loadRecovery,
  lockKeys,
  newVaultKey,
  proveRecovery,
  readVaultKey,
  revealMyShare,
  rotateVault,
  sealRecovery,
  sealTarget,
  setupRecovery,
  shareVaultKey,
  unlockIdentity,
  unlockWithRecoveryKey,
  writeOwnerEnvelope,
  type Epoch,
  type HeldKeys,
  type RecoveredVault,
  type RecoveryInfo,
} from "./crypto/session";
import type { AccountRecord } from "./crypto/vault";
import type { PublicKey, VaultInfo } from "./types";
import { StatusLine } from "./workspace";
import { Fingerprint, PinBadge, VerifyKeyDialog } from "./verify";

export type OpenVault = {
  keys: HeldKeys;
  vault: VaultInfo;
  vaultKey: Uint8Array;
  passwords: Record<string, string>;
  records: Record<string, AccountRecord>;
  versions: Record<string, number>;
};

type Props = {
  userId: string;
  isAdmin: boolean;
  recoveryReady: boolean;
  open: OpenVault | null;
  onOpen: (next: OpenVault | null) => void;
  onChanged: () => Promise<void>;
};

type Tab = "items" | "members" | "recovery";

type Member = { user_id: string; role: string; display_name: string; email: string; has_key: boolean };

// Verify describes a pending verify-key dialog and what happens after it.
type Verify = { key: PublicKey; label?: string; then?: () => Promise<void> };

export function VaultPage({ userId, isAdmin, recoveryReady, open, onOpen, onChanged }: Props) {
  const [tab, setTab] = useState<Tab>("items");
  // identity is set when the person's own key is unlocked but the vault key is
  // not theirs to open: a custodian confirming a share or recovering the vault.
  const [identity, setIdentity] = useState<HeldKeys | null>(null);
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

  if (!open && identity) {
    return (
      <div className="content">
        <div className="heading">
          <div>
            <h1>Vault</h1>
            <p className="stat-strip">your key is unlocked · the vault key is not shared with you</p>
          </div>
          <button
            className="btn"
            onClick={() => {
              lockKeys(identity);
              setIdentity(null);
              setNotice("key locked in this tab");
            }}
          >
            Lock
          </button>
        </div>
        <CustodianView
          userId={userId}
          held={identity}
          onRecovered={async (next) => {
            setIdentity(null);
            onOpen(next);
            setTab("recovery");
            setNotice("vault recovered; you are now an owner. Set up recovery again");
            await onChanged();
          }}
        />
        <footer className="bottom">
          <span />
          <StatusLine text={notice || "the server never sees your passphrase"} />
        </footer>
      </div>
    );
  }

  if (!open) {
    return (
      <div className="content">
        <h1>Vault</h1>
        <p className="intro">Passwords are encrypted in this browser. The server stores only encrypted copies and cannot open them.</p>
        <UnlockPanel
          userId={userId}
          onOpen={(next) => {
            onOpen(next);
            setNotice(recoveryReady ? "vault unlocked" : "unlocked; set up recovery before saving passwords");
            setTab(recoveryReady ? "items" : "recovery");
          }}
          onIdentityOnly={setIdentity}
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
            isAdmin={isAdmin}
            open={open}
            keys={keys}
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

type UnlockProps = {
  userId: string;
  onOpen: (next: OpenVault) => void;
  onIdentityOnly: (held: HeldKeys) => void;
};

function UnlockPanel({ userId, onOpen, onIdentityOnly }: UnlockProps) {
  const [passphrase, setPassphrase] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function finishUnlock(held: HeldKeys) {
    // The browser just checked this key against the approved fingerprint.
    pinKey(userId, userId, held.fingerprint);
    let vault: VaultInfo;
    try {
      vault = await ensureVault();
    } catch (err) {
      // Not shared with this person (a non-admin cannot even list the vault,
      // so trying to create one says it exists). Their own key still opens,
      // for custodian work.
      if (err instanceof ApiError && (err.code === "no_access" || err.code === "vault_exists")) {
        onIdentityOnly(held);
        return;
      }
      throw err;
    }
    let vaultKey: Uint8Array;
    try {
      vaultKey = await readVaultKey(held, vault.id, vault.key_version);
    } catch (err) {
      // A new key is minted only for a vault that never had one. Anywhere
      // else a missing envelope means "not shared with you yet".
      if (!(err instanceof ApiError) || err.status !== 404) throw err;
      if (vault.initialized || vault.role !== "owner") {
        onIdentityOnly(held);
        return;
      }
      vaultKey = await newVaultKey();
      await writeOwnerEnvelope(held, userId, vault.id, vault.key_version, vaultKey);
      vault.initialized = true;
    }
    // Reading never depends on recovery; only saving new passwords does.
    const items = await loadPasswords(vault, vaultKey);
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

// useRecovery loads the organization's recovery state.
function useRecovery(): [RecoveryInfo | null, () => Promise<void>, string] {
  const [info, setInfo] = useState<RecoveryInfo | null>(null);
  const [error, setError] = useState("");
  async function reload() {
    try {
      setInfo(await loadRecovery());
      setError("");
    } catch (err) {
      setError(explain(err));
    }
  }
  useEffect(() => {
    reload();
  }, []);
  return [info, reload, error];
}

function usePublicKeys(): PublicKey[] {
  const [keys, setKeys] = useState<PublicKey[]>([]);
  useEffect(() => {
    api<{ keys: PublicKey[] }>("/api/v1/crypto/keys")
      .then((row) => setKeys(row.keys.filter((item) => item.key_status === "approved" && item.user_status === "active")))
      .catch(() => setKeys([]));
  }, []);
  return keys;
}

// A rollback never opens the dialog (withRecoveryKey refuses it first); if one
// got this far it is shown as a changed key, never as a fresh one.
const dialogPin = (pin: RecoveryPinState): PinState => (pin.state === "rollback" ? { state: "changed", at: pin.at } : pin);

const custodianOf = (epoch: Epoch | null, userId: string) => epoch?.custodians.find((c) => c.user_id === userId);

// RecoveryStatus is the state line and banner from DESIGN.md's recovery row.
function RecoveryStatus({ info, sealNeeded }: { info: RecoveryInfo; sealNeeded: boolean }) {
  const { current, next } = info;
  let banner: { tone: "warn" | "bad" | "ok"; text: string } | null = null;
  if (next?.status === "pending") {
    banner = { tone: "warn", text: "● A new recovery key is waiting for both custodians to confirm their shares." };
  } else if (next?.status === "confirmed") {
    banner = { tone: "warn", text: "● Both custodians confirmed. An owner seals the vault key to the new recovery key to switch it on." };
  } else if (!current) {
    banner = { tone: "warn", text: "● Recovery isn't set up. New passwords are blocked." };
  } else if (current.status === "degraded") {
    banner = {
      tone: "bad",
      text: "▲ A custodian or the admin who set up recovery left. Recovery is off and new passwords are blocked. An admin sets it up again with two current custodians, then an owner rotates the vault key.",
    };
  } else if (current.status === "spent") {
    banner = { tone: "warn", text: "● Recovery was used, so its key is spent. Set up recovery again to save new passwords." };
  } else if (!info.recovery_ready) {
    banner = { tone: "bad", text: "▲ A custodian's key no longer matches their share. Set up recovery again." };
  } else if (sealNeeded) {
    banner = { tone: "warn", text: "● An owner seals the current vault key to the recovery key to finish." };
  }
  const shown = next ?? current;
  return (
    <div className="panel stack">
      <h2>Recovery</h2>
      {banner && <div className={banner.tone === "bad" ? "banner bad" : "banner"}>{banner.text}</div>}
      {shown ? (
        <>
          <p className="stat-strip">{`recovery key r${shown.epoch}  ·  ${shown.status}${info.recovery_ready && shown === current ? "  ·  ready" : ""}`}</p>
          <div className="data-table">
            {shown.custodians.map((c) => (
              <div key={c.user_id} className="data-row">
                <span>
                  <span className="service-name">{c.display_name || c.email}</span>
                  <span className="service-sub">share {c.share_index}</span>
                </span>
                <span>
                  {!c.active ? (
                    <span className="alert-text">▲ left</span>
                  ) : c.confirmed ? (
                    <span className="ok-text">✓ confirmed</span>
                  ) : (
                    <span className="warn-text">● waiting</span>
                  )}
                </span>
              </div>
            ))}
          </div>
          <Fingerprint value={shown.fingerprint} label="Recovery key fingerprint" />
        </>
      ) : (
        <p className="prose">
          Two custodians each hold one share of a recovery key. Together they can reopen the vault if nobody who holds the vault key can unlock it. One share
          alone cannot.
        </p>
      )}
    </div>
  );
}

type CustodianPanelsProps = {
  userId: string;
  held: HeldKeys;
  info: RecoveryInfo;
  keys: PublicKey[];
  reload: () => Promise<void>;
  run: (action: () => Promise<void>) => Promise<void>;
  onVerify: (key: PublicKey) => void;
  setNotice: (text: string) => void;
};

// CustodianPanels: confirm a new share, or reveal the current one to read to
// the other custodian during a recovery.
function CustodianPanels({ userId, held, info, keys, reload, run, onVerify, setNotice }: CustodianPanelsProps) {
  const [shareText, setShareText] = useState("");
  const pendingMine = info.next?.status === "pending" ? custodianOf(info.next, userId) : undefined;
  const currentMine = info.current?.status === "active" ? custodianOf(info.current, userId) : undefined;
  const creatorOf = (epoch: Epoch) => keys.find((key) => key.user_id === epoch.created_by);

  function needsCreator(epoch: Epoch): PublicKey | null {
    if (epoch.created_by === userId) return null;
    const creator = creatorOf(epoch);
    if (!creator || creator.fingerprint !== epoch.creator_fingerprint) return null;
    return pinState(userId, creator.user_id, creator.fingerprint).state === "verified" ? null : creator;
  }

  return (
    <>
      {pendingMine && !pendingMine.confirmed && info.next && (
        <div className="panel stack">
          <h2>Confirm your recovery share</h2>
          <p className="prose">
            You were chosen as custodian {pendingMine.share_index}. Confirming opens your share in this browser, checks that it came from the admin who set it up,
            and records the recovery key fingerprint. Nobody sees the share.
          </p>
          {needsCreator(info.next) ? (
            <button className="btn" onClick={() => onVerify(needsCreator(info.next as Epoch) as PublicKey)}>
              Verify {creatorOf(info.next)?.display_name || "the admin"} first
            </button>
          ) : (
            <button
              className="btn primary"
              onClick={() =>
                run(async () => {
                  await confirmMyShare(userId, held, info.organization_id);
                  await reload();
                  setNotice("share confirmed");
                })
              }
            >
              Confirm my share
            </button>
          )}
        </div>
      )}
      {currentMine && info.current && (
        <div className="panel stack">
          <h2>Your recovery share</h2>
          <p className="prose">Reveal it only while the other custodian is recovering the vault, and read it to them directly. Hide it right after.</p>
          {shareText ? (
            <>
              <Fingerprint value={shareText} label={`Share ${currentMine.share_index}`} />
              <button className="btn" onClick={() => setShareText("")}>
                Hide share
              </button>
            </>
          ) : needsCreator(info.current) ? (
            <button className="btn" onClick={() => onVerify(needsCreator(info.current as Epoch) as PublicKey)}>
              Verify {creatorOf(info.current)?.display_name || "the admin"} first
            </button>
          ) : (
            <button
              className="btn"
              onClick={() => run(async () => setShareText(await revealMyShare(userId, held, info.organization_id, (info.current as Epoch).epoch)))}
            >
              Show my share
            </button>
          )}
        </div>
      )}
    </>
  );
}

type SetupProps = {
  userId: string;
  held: HeldKeys;
  info: RecoveryInfo;
  keys: PublicKey[];
  reload: () => Promise<void>;
  run: (action: () => Promise<void>) => Promise<void>;
  onVerify: (key: PublicKey) => void;
  setNotice: (text: string) => void;
};

function SetupRecovery({ userId, held, info, keys, reload, run, onVerify, setNotice }: SetupProps) {
  const settled = (info.recovery_ready && !info.next) || info.next?.status === "pending" || info.next?.status === "confirmed";
  const [openForm, setOpenForm] = useState(!settled);
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const [formError, setFormError] = useState("");
  const verified = (id: string) => {
    const key = keys.find((item) => item.user_id === id);
    return key ? pinState(userId, key.user_id, key.fingerprint).state === "verified" : false;
  };

  if (!openForm) {
    return (
      <div className="panel stack">
        <h2>{info.next ? "Start over" : "Replace the recovery key"}</h2>
        <p className="prose">
          {info.next
            ? "Choose different custodians if the new recovery key was sent to the wrong people. The waiting setup is discarded."
            : "Set up a new recovery key when a custodian changes, or when a share may have been seen by someone else."}
        </p>
        <button className="btn" onClick={() => setOpenForm(true)}>
          Set up a new recovery key
        </button>
      </div>
    );
  }
  return (
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
          await setupRecovery(userId, held, info, a, b);
          await reload();
          setOpenForm(false);
          setFirst("");
          setSecond("");
          setNotice("recovery key created; both custodians confirm next");
        });
      }}
    >
      <h2>{info.current || info.next ? "Set up a new recovery key" : "Set up recovery"}</h2>
      <p className="prose">
        This browser creates a recovery key, splits it in two and sends one share to each custodian. Verify both custodians' keys first. Choose people other
        than yourself if you can: your browser briefly holds the whole key.
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
        {keys.length < 2 ? "A second person with an approved key is needed" : "Create and send the shares"}
      </button>
    </form>
  );
}

type RecoveryProps = {
  userId: string;
  isAdmin: boolean;
  open: OpenVault;
  keys: PublicKey[];
  canRotate: boolean;
  run: (action: () => Promise<void>) => Promise<void>;
  onVerify: (key: PublicKey) => void;
  onOpen: (next: OpenVault | null) => void;
  onChanged: () => Promise<void>;
  setNotice: (text: string) => void;
};

function RecoveryTab({ userId, isAdmin, open, keys, canRotate, run, onVerify, onOpen, onChanged, setNotice }: RecoveryProps) {
  const [info, reloadInfo, infoError] = useRecovery();
  const [sealedEpoch, setSealedEpoch] = useState<number | null | undefined>(undefined);
  const [verifyRecovery, setVerifyRecovery] = useState<{ epoch: Epoch; then: () => Promise<void> } | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [again, setAgain] = useState("");
  const [formError, setFormError] = useState("");

  async function reload() {
    await reloadInfo();
    await onChanged();
  }

  useEffect(() => {
    api<{ epoch: number }>(`/api/v1/vaults/${open.vault.id}/recovery-envelope`)
      .then((row) => setSealedEpoch(row.epoch))
      .catch(() => setSealedEpoch(null));
  }, [open.vault.id, open.vault.key_version, info?.current?.epoch, info?.current?.status, info?.next?.status]);

  if (infoError) return <div className="banner bad">{infoError}</div>;
  if (!info || sealedEpoch === undefined) return <p className="status-line">&gt; loading recovery</p>;

  const target = sealTarget(info);
  const sealNeeded = Boolean(target && sealedEpoch !== target.epoch);

  // withRecoveryKey runs action once the recovery key is pinned, asking a
  // custodian to read its fingerprint first if needed.
  function withRecoveryKey(epoch: Epoch, action: () => Promise<void>) {
    const pin = recoveryPinState(userId, info!.organization_id, epoch.fingerprint, epoch.epoch);
    if (pin.state === "rollback") {
      run(async () => {
        throw new Error("recovery_rollback");
      });
      return;
    }
    if (pin.state === "verified") {
      run(action);
      return;
    }
    setVerifyRecovery({ epoch, then: action });
  }

  return (
    <div className="stack wide">
      <RecoveryStatus info={info} sealNeeded={sealNeeded} />

      {sealNeeded && canRotate && target && (
        <div className="panel stack">
          <h2>Seal the vault key to recovery</h2>
          <p className="prose">This lets the custodians reopen the vault later. It needs only the recovery key's public half; no custodian has to be present.</p>
          <button
            className="btn primary"
            onClick={() =>
              withRecoveryKey(target, async () => {
                await sealRecovery(userId, info.organization_id, open.vault, open.vaultKey, target);
                await reload();
                setSealedEpoch(target.epoch);
                setNotice("vault key sealed to recovery; passwords can be saved");
              })
            }
          >
            Seal vault key
          </button>
        </div>
      )}

      <CustodianPanels userId={userId} held={open.keys} info={info} keys={keys} reload={reload} run={run} onVerify={onVerify} setNotice={setNotice} />

      {isAdmin && <SetupRecovery userId={userId} held={open.keys} info={info} keys={keys} reload={reload} run={run} onVerify={onVerify} setNotice={setNotice} />}

      {canRotate && (
        <div className="panel stack">
          <h2>Rotate the vault key</h2>
          <p className="prose">
            Rotate after someone leaves or replaces their key. Every member's key must be verified in this browser first.
            {target ? " The new key is also sealed to the recovery key." : " Recovery is not usable, so the new key is sealed only to members."}
          </p>
          <button
            className="btn primary"
            onClick={() => {
              const go = async () => {
                const next = await rotateVault(userId, info.organization_id, open.vault, open.vaultKey, target);
                const items = await loadPasswords({ ...open.vault, key_version: next.keyVersion }, next.vaultKey);
                onOpen({ ...open, vault: { ...open.vault, key_version: next.keyVersion, rotation_required: false }, vaultKey: next.vaultKey, ...items });
                setNotice("vault key rotated; old envelopes deleted");
                await reload();
              };
              if (target) withRecoveryKey(target, go);
              else run(go);
            }}
          >
            Rotate key
          </button>
        </div>
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
        {formError && <p className="import-error">{formError}</p>}
        <button className="btn primary">Change passphrase</button>
      </form>

      {verifyRecovery && (
        <VerifyKeyDialog
          viewerId={userId}
          userId={`recovery:${info.organization_id}`}
          name="recovery key"
          fingerprint={verifyRecovery.epoch.fingerprint}
          title="Verify the recovery key"
          prompt="Ask a recovery custodian to read the recovery key fingerprint from their Recovery tab, on a call or in person. Every group must match."
          pin={dialogPin(recoveryPinState(userId, info.organization_id, verifyRecovery.epoch.fingerprint, verifyRecovery.epoch.epoch))}
          onConfirm={async () => {
            pinRecoveryKey(userId, info.organization_id, verifyRecovery.epoch.fingerprint, verifyRecovery.epoch.epoch);
            await verifyRecovery.then();
          }}
          onClose={() => setVerifyRecovery(null)}
        />
      )}
    </div>
  );
}

type CustodianViewProps = {
  userId: string;
  held: HeldKeys;
  onRecovered: (next: OpenVault) => Promise<void>;
};

// CustodianView is the vault page for someone whose own key is unlocked but who
// holds no vault key: custodians confirm shares and recover the vault here.
function CustodianView({ userId, held, onRecovered }: CustodianViewProps) {
  const [info, reload, infoError] = useRecovery();
  const keys = usePublicKeys();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [verify, setVerify] = useState<PublicKey | null>(null);
  const [, setPinsChanged] = useState(0);

  async function run(action: () => Promise<void>) {
    setError("");
    try {
      await action();
    } catch (err) {
      setError(explain(err));
    }
  }

  if (infoError) return <div className="banner bad">{infoError}</div>;
  if (!info) return <p className="status-line">&gt; loading recovery</p>;
  const custodian = custodianOf(info.next, userId) || custodianOf(info.current, userId);
  const canRecover = info.recovery_ready && info.current?.status === "active" && Boolean(custodianOf(info.current, userId));

  return (
    <div className="stack wide">
      {error && <div className="banner bad">{error}</div>}
      {notice && <p className="status-line">&gt; {notice}</p>}
      {!custodian && (
        <div className="panel">
          <p className="prose">The vault key is not shared with you yet. Ask a vault owner to add you and share it from Members.</p>
        </div>
      )}
      {custodian && (
        <>
          <RecoveryStatus info={info} sealNeeded={false} />
          <CustodianPanels userId={userId} held={held} info={info} keys={keys} reload={reload} run={run} onVerify={setVerify} setNotice={setNotice} />
          {canRecover && info.vaults[0] && (
            <RecoverFlow userId={userId} held={held} info={info} vaultId={info.vaults[0].id} keys={keys} onVerify={setVerify} onRecovered={onRecovered} />
          )}
        </>
      )}
      {verify && (
        <VerifyKeyDialog
          viewerId={userId}
          userId={verify.user_id}
          name={verify.display_name || verify.email}
          fingerprint={verify.fingerprint}
          onConfirm={async () => {
            pinKey(userId, verify.user_id, verify.fingerprint);
            setPinsChanged((n) => n + 1);
          }}
          onClose={() => setVerify(null)}
        />
      )}
    </div>
  );
}

type RecoverFlowProps = {
  userId: string;
  held: HeldKeys;
  info: RecoveryInfo;
  vaultId: string;
  keys: PublicKey[];
  onVerify: (key: PublicKey) => void;
  onRecovered: (next: OpenVault) => Promise<void>;
};

// RecoverFlow is DR-7 flow 2: prove the recovery key with both shares, then
// rotate within the 15-minute grant. Shares and keys are wiped on every exit.
function RecoverFlow({ userId, held, info, vaultId, keys, onVerify, onRecovered }: RecoverFlowProps) {
  const [started, setStarted] = useState(false);
  const [otherShare, setOtherShare] = useState("");
  const [showShare, setShowShare] = useState(false);
  const [recovered, setRecovered] = useState<RecoveredVault | null>(null);
  const [keep, setKeep] = useState<Record<string, boolean>>({});
  const [left, setLeft] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  function wipe() {
    setOtherShare("");
    setShowShare(false);
    setRecovered((current) => {
      if (current) current.oldKey.fill(0);
      return null;
    });
  }

  useEffect(() => wipe, []);

  useEffect(() => {
    if (!recovered) return;
    const tick = () => {
      const seconds = Math.max(0, Math.round((new Date(recovered.expiresAt).getTime() - Date.now()) / 1000));
      setLeft(seconds);
      if (seconds === 0) {
        wipe();
        setError("The 15-minute recovery window ended. Start again.");
      }
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [recovered]);

  const keyOf = (id: string) => keys.find((key) => key.user_id === id);
  const verified = (id: string) => {
    const key = keyOf(id);
    return key ? pinState(userId, key.user_id, key.fingerprint).state === "verified" : false;
  };

  if (!started) {
    return (
      <div className="panel stack">
        <h2>Recover the team vault</h2>
        <p className="prose">
          Use this only when nobody who holds the vault key can unlock it. You need the other custodian's share, read to you directly. Afterwards you become a
          vault owner and the recovery key is used up, so an admin sets up recovery again.
        </p>
        <button className="btn" onClick={() => setStarted(true)}>
          Start recovery
        </button>
      </div>
    );
  }

  if (!recovered) {
    return (
      <form
        className="panel stack"
        onSubmit={(event) => {
          event.preventDefault();
          const text = otherShare;
          setOtherShare("");
          setBusy(true);
          setError("");
          proveRecovery(userId, held, info, vaultId, text)
            .then((next) => {
              setRecovered(next);
              const initial: Record<string, boolean> = {};
              for (const member of next.members) initial[member.user_id] = member.user_id !== userId && verified(member.user_id);
              setKeep(initial);
            })
            .catch((err) => setError(explain(err)))
            .finally(() => setBusy(false));
        }}
      >
        <h2>Recover the team vault</h2>
        {error && <p className="import-error">{error}</p>}
        <p className="prose">Your own share is opened in this browser. Type the other custodian's share as they read it to you.</p>
        <label className="field">
          <span>Other custodian's share</span>
          <input
            type={showShare ? "text" : "password"}
            value={otherShare}
            onChange={(event) => setOtherShare(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="off"
            required
          />
        </label>
        <div className="modal-actions">
          <button type="button" className="btn subtle" onClick={() => setShowShare((current) => !current)}>
            {showShare ? "Hide" : "Show"}
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => {
              wipe();
              setStarted(false);
              setError("");
            }}
          >
            Cancel
          </button>
          <button className="btn primary" disabled={busy || !otherShare}>
            {busy ? "Proving…" : "Prove recovery key"}
          </button>
        </div>
      </form>
    );
  }

  const others = recovered.members.filter((member) => member.user_id !== userId);
  return (
    <div className="panel stack">
      <h2>Rotate and take over</h2>
      <p className="stat-strip">{`> recovery window ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} left`}</p>
      {error && <p className="import-error">{error}</p>}
      <p className="prose">
        The vault key opened. Choose who keeps access to the new key. Only people whose key you verified can be kept; the rest can be added back afterwards.
      </p>
      <div className="data-table">
        {others.length === 0 && <p className="empty-state">No other members.</p>}
        {others.map((member) => {
          const key = keyOf(member.user_id);
          const ok = verified(member.user_id);
          return (
            <div key={member.user_id} className="data-row">
              <label className="check">
                <input
                  type="checkbox"
                  checked={Boolean(keep[member.user_id]) && ok}
                  disabled={!ok}
                  onChange={(event) => setKeep({ ...keep, [member.user_id]: event.target.checked })}
                />{" "}
                {member.display_name || member.email}
              </label>
              <span>
                {key ? <PinBadge viewerId={userId} userId={member.user_id} fingerprint={key.fingerprint} /> : <span className="warn-text">● no approved key</span>}{" "}
                {key && !ok && (
                  <button className="text-button" onClick={() => onVerify(key)}>
                    Verify
                  </button>
                )}
              </span>
            </div>
          );
        })}
      </div>
      <div className="modal-actions">
        <button
          className="btn"
          onClick={() => {
            wipe();
            setStarted(false);
          }}
        >
          Cancel
        </button>
        <button
          className="btn primary"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            setError("");
            const chosen = others.filter((member) => keep[member.user_id] && verified(member.user_id)).map((member) => member.user_id);
            (async () => {
              const next = await finishRecovery(userId, held, recovered, chosen);
              setRecovered(null);
              const vault = await ensureVault();
              const items = await loadPasswords({ ...vault, key_version: next.keyVersion }, next.vaultKey);
              await onRecovered({ keys: held, vault: { ...vault, key_version: next.keyVersion }, vaultKey: next.vaultKey, ...items });
            })()
              .catch((err) => setError(explain(err)))
              .finally(() => setBusy(false));
          }}
        >
          {busy ? "Rotating…" : "Rotate and take over"}
        </button>
      </div>
    </div>
  );
}
