import { lazy, Suspense, useEffect, useState } from "react";
import { api, clearCsrf, explain, setCsrf } from "./api";
import { secretKey, splitBackup } from "./import";
import { TeamPage } from "./team";
import type { Account, SessionUser, WorkspaceData } from "./types";
import type { OpenVault } from "./vault";
import { CategoryNav, Workspace } from "./workspace";

const VaultPage = lazy(() => import("./vault").then((mod) => ({ default: mod.VaultPage })));

type View = "services" | "vault" | "team";

export function App() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [ready, setReady] = useState(false);
  const [data, setData] = useState<WorkspaceData | null>(null);
  const [open, setOpen] = useState<OpenVault | null>(null);
  const [view, setView] = useState<View>("services");
  const [category, setCategory] = useState("all");

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
    if (hash === "vault" || hash === "team" || hash === "services") setView(hash);
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
    const saved = await storePassword(open.vault, open.vaultKey, account.id, account.vault_item_id, password, itemVersion);
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
  if (user.status === "pending_enrollment") {
    return <Enroll onDone={loadSession} />;
  }
  if (user.status !== "active") {
    return <Pending user={user} onDone={loadSession} />;
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
            {user.role === "admin" && (
              <button className={view === "team" ? "active" : ""} onClick={() => choose("team")}>
                Team
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
          <span>Invitation token</span>
          <textarea value={token} onChange={(event) => setToken(event.target.value)} rows={3} placeholder="Paste the token if this is your first sign-in" />
        </label>
        <button className="btn primary">Sign in</button>
      </form>
    </div>
  );
}

function Enroll({ onDone }: { onDone: () => Promise<void> }) {
  const [passphrase, setPassphrase] = useState("");
  const [again, setAgain] = useState("");
  const [recovery, setRecovery] = useState("");
  const [draft, setDraft] = useState<Record<string, string | number> | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  return (
    <div className="auth-wrap">
      <AuthBrand />
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
          const submit = async () => {
            let body = draft;
            if (!body) {
              const { createIdentity } = await import("./crypto/session");
              const created = await createIdentity(passphrase);
              setRecovery(created.recoveryKey);
              setDraft(created.body);
              return;
            }
            if (!saved) {
              setError("Save the recovery key, then continue.");
              return;
            }
            const { fingerprint: _ignored, ...posted } = body;
            await api("/api/v1/crypto/identity", "POST", posted);
            await onDone();
          };
          submit()
            .catch((err) => setError(explain(err)))
            .finally(() => setBusy(false));
        }}
      >
        <h1>Create your personal key</h1>
        <p className="intro">The passphrase never leaves this browser. Your personal recovery key is shown once.</p>
        {error && <div className="banner bad">{error}</div>}
        <label className="field">
          <span>Passphrase</span>
          <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete="new-password" required disabled={draft !== null} />
        </label>
        <label className="field">
          <span>Repeat</span>
          <input type="password" value={again} onChange={(event) => setAgain(event.target.value)} autoComplete="new-password" required disabled={draft !== null} />
        </label>
        {recovery && (
          <>
            <p className="secret-once">{recovery}</p>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={saved} onChange={(event) => setSaved(event.target.checked)} /> I saved my personal recovery key
            </label>
          </>
        )}
        <button className="btn primary" disabled={busy || (recovery !== "" && !saved)}>
          {busy ? "Deriving key…" : recovery ? "Submit key for approval" : "Create key"}
        </button>
      </form>
    </div>
  );
}

function Pending({ user, onDone }: { user: SessionUser; onDone: () => Promise<void> }) {
  const [error, setError] = useState("");
  return (
    <div className="auth-wrap">
      <AuthBrand />
      <div className="auth-card stack">
        <h1>Your key is waiting for an admin</h1>
        <p className="intro">The ledger stays closed until your key is approved. If you are the only admin, approve your own key.</p>
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
            Approve my key
          </button>
        )}
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
