import { lazy, Suspense, useEffect, useState } from "react";
import { ApiError, api, clearCsrf, explain, setCsrf } from "./api";
import { secretKey, splitBackup } from "./import";
import { AgentsPage } from "./agents";
import { TeamPage } from "./team";
import type { Account, SessionUser, WorkspaceData } from "./types";
import type { OpenVault } from "./vault";
import { Fingerprint } from "./verify";
import { CategoryNav, Workspace } from "./workspace";

const VaultPage = lazy(() => import("./vault").then((mod) => ({ default: mod.VaultPage })));

type View = "services" | "vault" | "team" | "agents";

export function App() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [ready, setReady] = useState(false);
  const [data, setData] = useState<WorkspaceData | null>(null);
  const [open, setOpen] = useState<OpenVault | null>(null);
  const [view, setView] = useState<View>("services");
  const [category, setCategory] = useState("all");
  const [reenroll, setReenroll] = useState(false);

  async function loadSession() {
    try {
      const session = await api<{ csrf_token: string; user: SessionUser }>("/api/v1/session");
      setCsrf(session.csrf_token);
      setUser(session.user);
      if (session.user.status === "active") {
        setData(await api<WorkspaceData>("/api/v1/workspace"));
      }
    } catch {
      clearCsrf();
      setUser(null);
      setData(null);
    } finally {
      setReady(true);
    }
  }

  useEffect(() => {
    const hash = window.location.hash.replace("#/", "");
    if (hash === "vault" || hash === "team" || hash === "services" || hash === "agents") setView(hash);
    loadSession();
  }, []);

  function choose(next: View) {
    setView(next);
    window.location.hash = next === "services" ? "#/" : `#/${next}`;
  }

  async function reloadWorkspace() {
    const next = await api<WorkspaceData>("/api/v1/workspace");
    setData(next);
    return next;
  }

  async function importFile(file: File) {
    const parsed = JSON.parse(await file.text()) as unknown;
    const { document, secrets } = splitBackup(parsed);
    if (secrets.length > 0 && (!open || !data?.organization.recovery_ready)) {
      throw new Error("Unlock the vault and assign two custodians. No passwords were sent.");
    }
    await api("/api/v1/imports/services", "POST", document);
    const fresh = await reloadWorkspace();
    if (!open || secrets.length === 0) return;
    const used = new Set<string>();
    const versions = { ...open.versions };
    for (const hit of secrets) {
      const service = fresh.services.find((item) => item.name === hit.service);
      const account = fresh.accounts.find((item) => {
        if (!service || item.service_id !== service.id || used.has(item.id)) return false;
        return secretKey({ service: service.name, label: item.label, login: item.login_hint }) === secretKey(hit);
      });
      if (!account) {
        throw new Error(`Could not link the password for account "${hit.label}". The metadata is already imported.`);
      }
      used.add(account.id);
      const { savePassword: storePassword } = await import("./crypto/session");
      const itemVersion = account.vault_item_id ? versions[account.vault_item_id] : undefined;
      const saved = await storePassword(open.vault, open.vaultKey, account.id, account.vault_item_id, hit.password, itemVersion);
      versions[saved.id] = saved.version;
      account.vault_item_id = saved.id;
      account.vault_id = open.vault.id;
    }
    const passwords = { ...open.passwords };
    for (const account of fresh.accounts) {
      const hit = secrets.find((item) => {
        const service = fresh.services.find((row) => row.id === account.service_id);
        return service && secretKey({ service: service.name, label: account.label, login: account.login_hint }) === secretKey(item);
      });
      if (hit && account.vault_item_id) passwords[account.vault_item_id] = hit.password;
    }
    setOpen({ ...open, passwords, versions });
    setData(fresh);
  }

  async function saveAccountPassword(account: Account, password: string) {
    if (!open || !data?.organization.recovery_ready) {
      throw new Error("recovery_not_ready");
    }
    const { savePassword: storePassword } = await import("./crypto/session");
    const itemVersion = account.vault_item_id ? open.versions[account.vault_item_id] : undefined;
    let saved: { id: string; version: number };
    try {
      saved = await storePassword(open.vault, open.vaultKey, account.id, account.vault_item_id, password, itemVersion);
    } catch (err) {
      if (err instanceof ApiError && err.code === "item_conflict") {
        // Load what the other person saved; the field keeps this person's text.
        const { loadPasswords } = await import("./crypto/session");
        const latest = await loadPasswords(open.vault, open.vaultKey);
        setOpen({ ...open, ...latest });
        throw new ApiError(409, "item_conflict_reloaded");
      }
      throw err;
    }
    setOpen({
      ...open,
      passwords: { ...open.passwords, [saved.id]: password },
      versions: { ...open.versions, [saved.id]: saved.version },
    });
  }

  if (!ready) {
    return (
      <div className="auth-wrap">
        <AuthBrand />
        <p className="status-line">
          &gt; loading<span className="cursor" aria-hidden="true" />
        </p>
      </div>
    );
  }
  if (!user) {
    return <Login error={new URLSearchParams(window.location.search).get("error")} />;
  }
  if (user.status === "pending_enrollment" || reenroll) {
    return (
      <Enroll
        onDone={async () => {
          setReenroll(false);
          await loadSession();
        }}
      />
    );
  }
  if (user.status !== "active") {
    return <Pending user={user} onDone={loadSession} onRestart={() => setReenroll(true)} />;
  }

  return (
    <div className="app">
      <aside className="side">
        <div className="brand">
          <p className="wordmark small">BORISYELTSIN</p>
        </div>
        <div>
          <nav className="nav" aria-label="Sections">
            <button className={view === "services" ? "active" : ""} onClick={() => choose("services")}>
              Services
            </button>
            <button className={view === "vault" ? "active" : ""} onClick={() => choose("vault")}>
              Vault
            </button>
            {user.role === "admin" && status !== "rejected" && (
              <button className={view === "team" ? "active" : ""} onClick={() => choose("team")}>
                Team
              </button>
            )}
            {user.status === "active" && (
              <button className={view === "agents" ? "active" : ""} onClick={() => choose("agents")}>
                Agents
              </button>
            )}
          </nav>
        </div>
        {view === "services" && data && (
          <div className="side-categories">
            <div className="side-label">Categories</div>
            <CategoryNav category={category} services={data.services} accounts={data.accounts} subscriptions={data.subscriptions} onPick={setCategory} />
          </div>
        )}
        <div className="side-foot">
          <span className="who">
            {user.display_name}
            <br />
            {user.email}
          </span>
          <button
            className="text-button"
            onClick={() => {
              api("/api/v1/session/logout", "POST", {}).finally(() => {
                if (open) {
                  import("libsodium-wrappers-sumo").then(async (mod) => {
                    await mod.default.ready;
                    mod.default.memzero(open.keys.privateKey);
                  });
                }
                clearCsrf();
                setOpen(null);
                setUser(null);
                setData(null);
              });
            }}
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">
        {view === "services" && data && (
          <Workspace
            data={data}
            category={category}
            readOnly={user.role === "readonly"}
            passwords={open?.passwords ?? {}}
            canStore={Boolean(open && data.organization.recovery_ready)}
            onReload={async () => {
              await reloadWorkspace();
            }}
            onSavePassword={saveAccountPassword}
            onImport={importFile}
          />
        )}
        {view === "vault" && data && (
          <Suspense fallback={<p className="content modal-hint">Loading vault…</p>}>
            <VaultPage
              isAdmin={user.role === "admin"}
              userId={user.id}
              recoveryReady={data.organization.recovery_ready}
              open={open}
              onOpen={setOpen}
              onChanged={async () => {
                await reloadWorkspace();
              }}
            />
          </Suspense>
        )}
        {view === "team" && user.role === "admin" && <TeamPage selfId={user.id} />}
        {view === "agents" && user.status === "active" && <AgentsPage isAdmin={user.role === "admin"} readOnly={user.role === "readonly"} />}
      </main>
    </div>
  );
}

function Login({ error }: { error: string | null }) {
  const [token, setToken] = useState("");
  const [message, setMessage] = useState(error === "access_denied" ? "Access denied." : "");

  return (
    <div className="auth-wrap">
      <AuthBrand />
      <form
        className="auth-card"
        onSubmit={(event) => {
          event.preventDefault();
          const go = async () => {
            if (token.trim()) {
              await api("/api/v1/auth/invite", "POST", { token: token.trim() });
            }
            window.location.assign("/api/v1/auth/login");
          };
          go().catch((err) => setMessage(explain(err)));
        }}
      >
        <h1>Sign in with an invitation</h1>
        <p className="intro">There is no public registration. Authentik checks the second factor.</p>
        {message && <div className="banner bad">{message}</div>}
        <label className="field">
          <span>Invitation key</span>
          <input
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder="eggs-watermelon, if this is your first sign-in"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
          />
        </label>
        <button className="btn primary">Sign in</button>
      </form>
    </div>
  );
}

// StepRail shows where the first-run path is: invite, key, approval.
function StepRail({ step }: { step: 1 | 2 | 3 }) {
  const steps = ["invite", "key", "approval"];
  return (
    <ol className="step-rail" aria-label="Setup progress">
      {steps.map((label, index) => {
        const n = index + 1;
        const state = n < step ? "done" : n === step ? "current" : "next";
        return (
          <li key={label} className={state} aria-current={state === "current" ? "step" : undefined}>
            [{state === "done" ? "✓" : n} {label}]
          </li>
        );
      })}
    </ol>
  );
}

type Draft = { body: Record<string, string | number>; recoveryKey: string; fingerprint: string };

// Enroll creates the personal key in three steps. Each step that cannot be
// undone gets its own screen: the passphrase locks once the key exists, the
// recovery key is shown once and must be confirmed, and the fingerprint is
// shown for the admin to compare.
function Enroll({ onDone }: { onDone: () => Promise<void> }) {
  const [passphrase, setPassphrase] = useState("");
  const [again, setAgain] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const groups = draft ? draft.recoveryKey.match(/.{1,4}/g) ?? [] : [];
  const lastGroup = groups[groups.length - 1] ?? "";

  function startOver() {
    setDraft(null);
    setConfirmed(false);
    setTyped("");
    setPassphrase("");
    setAgain("");
    setError("");
  }

  return (
    <div className="auth-wrap">
      <AuthBrand />
      <StepRail step={2} />
      {!draft && (
        <form
          className="auth-card"
          onSubmit={(event) => {
            event.preventDefault();
            if (passphrase.length < 12) {
              setError("The passphrase must be at least 12 characters.");
              return;
            }
            if (passphrase !== again) {
              setError("The passphrases do not match.");
              return;
            }
            setBusy(true);
            setError("");
            import("./crypto/session")
              .then(async ({ createIdentity }) => {
                const created = await createIdentity(passphrase);
                setDraft({ body: created.body, recoveryKey: created.recoveryKey, fingerprint: String(created.body.fingerprint) });
                setPassphrase("");
                setAgain("");
              })
              .catch((err) => setError(explain(err)))
              .finally(() => setBusy(false));
          }}
        >
          <h1>Create your personal key</h1>
          <p className="intro">Your passphrase unlocks the vault on this and other devices. It never leaves this browser and is separate from your Authentik password.</p>
          {error && <div className="banner bad">{error}</div>}
          <label className="field">
            <span>Passphrase (12+ characters)</span>
            <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete="new-password" required />
          </label>
          <label className="field">
            <span>Repeat</span>
            <input type="password" value={again} onChange={(event) => setAgain(event.target.value)} autoComplete="new-password" required />
          </label>
          <button className="btn primary" disabled={busy}>
            {busy ? "Deriving key… (a few seconds)" : "Create key"}
          </button>
        </form>
      )}
      {draft && !confirmed && (
        <form
          className="auth-card"
          onSubmit={(event) => {
            event.preventDefault();
            if (typed.trim() !== lastGroup) {
              setError("That is not the last group of your recovery key.");
              return;
            }
            setError("");
            setConfirmed(true);
          }}
        >
          <h1>Save your recovery key</h1>
          <div className="banner">If you lose both your passphrase and this key, nobody, including admins, can open your passwords. Resetting your Authentik password does not help.</div>
          <p className="secret-once" aria-label="Recovery key">
            {groups.join(" ")}
          </p>
          <div className="row-actions">
            <button
              type="button"
              className="btn"
              onClick={() => {
                navigator.clipboard?.writeText(draft.recoveryKey).then(
                  () => setError(""),
                  () => setError("Copy failed. Select the key and copy it by hand."),
                );
              }}
            >
              Copy
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => {
                const link = document.createElement("a");
                link.href = URL.createObjectURL(new Blob([`BorisYeltsin recovery key\n${draft.recoveryKey}\n`], { type: "text/plain" }));
                link.download = "borisyeltsin-recovery-key.txt";
                link.click();
                URL.revokeObjectURL(link.href);
              }}
            >
              Download .txt
            </button>
          </div>
          <label className="field">
            <span>Type the last group to confirm you saved it</span>
            <input value={typed} onChange={(event) => setTyped(event.target.value)} autoComplete="off" spellCheck={false} autoCapitalize="off" required />
          </label>
          {error && <p className="import-error">{error}</p>}
          <button className="btn primary">Continue</button>
          <button type="button" className="text-button" onClick={startOver}>
            Start over (this key will not be used)
          </button>
        </form>
      )}
      {draft && confirmed && (
        <div className="auth-card">
          <h1>Your key fingerprint</h1>
          <p className="intro">An admin approves your key after comparing this fingerprint with you, on a call or in person.</p>
          <Fingerprint value={draft.fingerprint} label="Your fingerprint" />
          {error && <div className="banner bad">{error}</div>}
          <button
            className="btn primary"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              setError("");
              const { fingerprint: _ignored, ...posted } = draft.body;
              api("/api/v1/crypto/identity", "POST", posted)
                .then(onDone)
                .catch((err) => setError(explain(err)))
                .finally(() => setBusy(false));
            }}
          >
            {busy ? "Sending…" : "Send key for approval"}
          </button>
        </div>
      )}
    </div>
  );
}

// Pending turns waiting into the verification step the admin needs anyway.
function Pending({ user, onDone, onRestart }: { user: SessionUser; onDone: () => Promise<void>; onRestart: () => void }) {
  const [error, setError] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [status, setStatus] = useState("");
  const [checked, setChecked] = useState(Date.now());
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    api<{ fingerprint?: string; status: string }>("/api/v1/crypto/me")
      .then((me) => {
        setFingerprint(me.fingerprint ?? "");
        setStatus(me.status);
      })
      .catch((err) => setError(explain(err)));
    const poll = window.setInterval(() => {
      onDone().finally(() => setChecked(Date.now()));
    }, 15000);
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      window.clearInterval(poll);
      window.clearInterval(tick);
    };
  }, []);

  return (
    <div className="auth-wrap">
      <AuthBrand />
      <StepRail step={3} />
      <div className="auth-card">
        <h1>{status === "rejected" ? "Your key was rejected" : "Waiting for an admin"}</h1>
        <p className="intro">
          {status === "rejected"
            ? "Ask your admin why, then create a new key and compare its fingerprint with them."
            : "Read this fingerprint to your admin when they verify you. This page opens the app by itself once your key is approved."}
        </p>
        {fingerprint && status !== "rejected" && <Fingerprint value={fingerprint} label="Your fingerprint" />}
        {status === "rejected" && (
          <button className="btn primary" onClick={onRestart}>
            Create a new key
          </button>
        )}
        {error && <div className="banner bad">{error}</div>}
        {user.role === "admin" && (
          <button
            className="btn primary"
            onClick={() => {
              api(`/api/v1/crypto/users/${user.id}/approve`, "POST", {})
                .then(onDone)
                .catch((err) => setError(explain(err)));
            }}
          >
            Approve my key (only while you are the sole user)
          </button>
        )}
        <p className="status-line" role="status">
          &gt; waiting for approval · checked {Math.max(0, Math.round((now - checked) / 1000))}s ago
          <span className="cursor" aria-hidden="true" />
        </p>
      </div>
    </div>
  );
}

function AuthBrand() {
  return (
    <header className="auth-brand">
      <p className="wordmark large">BORISYELTSIN</p>
      <p className="tagline">Everything is under control. Allegedly.</p>
    </header>
  );
}
