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
      throw new Error("Откройте сейф и назначьте двух хранителей. Пароли не отправлены.");
    }
    await api("/api/v1/imports/services", "POST", document);
    const fresh = await reloadWorkspace();
    if (!open || secrets.length === 0) return;
    const used = new Set<string>();
    for (const hit of secrets) {
      const service = fresh.services.find((item) => item.name === hit.service);
      const account = fresh.accounts.find((item) => {
        if (!service || item.service_id !== service.id || used.has(item.id)) return false;
        return secretKey({ service: service.name, label: item.label, login: item.login_hint }) === secretKey(hit);
      });
      if (!account) {
        throw new Error(`Не удалось привязать пароль аккаунта «${hit.label}». Метаданные уже импортированы.`);
      }
      used.add(account.id);
      const { savePassword: storePassword } = await import("./crypto/session");
      const itemId = await storePassword(open.vault, open.vaultKey, account.id, account.vault_item_id, hit.password);
      account.vault_item_id = itemId;
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
    setOpen({ ...open, passwords });
    setData(fresh);
  }

  async function saveAccountPassword(account: Account, password: string) {
    if (!open || !data?.organization.recovery_ready) {
      throw new Error("recovery_not_ready");
    }
    const { savePassword: storePassword } = await import("./crypto/session");
    const itemId = await storePassword(open.vault, open.vaultKey, account.id, account.vault_item_id, password);
    setOpen({ ...open, passwords: { ...open.passwords, [itemId]: password } });
  }

  if (!ready) {
    return (
      <div className="auth-wrap">
        <p className="modal-hint">Загрузка…</p>
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
          <span className="brand-mark">▦</span> Сервисы
        </div>
        <div>
          <div className="side-label">Рабочее пространство</div>
          {view === "services" && data && (
            <CategoryNav category={category} services={data.services} accounts={data.accounts} subscriptions={data.subscriptions} onPick={setCategory} />
          )}
          <div className="nav" style={{ marginTop: 18 }}>
            <button className={view === "services" ? "active" : ""} onClick={() => choose("services")}>
              Сервисы
            </button>
            <button className={view === "vault" ? "active" : ""} onClick={() => choose("vault")}>
              Сейф
            </button>
            {user.role === "admin" && (
              <button className={view === "team" ? "active" : ""} onClick={() => choose("team")}>
                Команда
              </button>
            )}
          </div>
        </div>
        <div className="side-foot">
          {user.display_name}
          <br />
          {user.email}
          <br />
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
            Выйти
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
          <Suspense fallback={<p className="content modal-hint">Загрузка сейфа…</p>}>
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
  const [message, setMessage] = useState(error === "access_denied" ? "Доступ закрыт." : "");

  return (
    <div className="auth-wrap">
      <form
        className="auth-card grid gap-4"
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
        <p className="eyebrow">BorisEltsyn</p>
        <h1>Вход по приглашению</h1>
        <p className="intro">Публичной регистрации нет. Второй фактор проверяет Authentik.</p>
        {message && <div className="banner bad">{message}</div>}
        <label className="field">
          <span>Токен приглашения</span>
          <textarea value={token} onChange={(event) => setToken(event.target.value)} rows={3} placeholder="Вставьте токен, если входите впервые" />
        </label>
        <button className="btn primary">Войти</button>
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
      <form
        className="auth-card grid gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          if (passphrase.length < 12) {
            setError("Парольная фраза должна быть не короче 12 символов.");
            return;
          }
          if (passphrase !== again) {
            setError("Фразы не совпали.");
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
              setError("Сохраните ключ восстановления, затем продолжите.");
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
        <p className="eyebrow">Ключ</p>
        <h1>Создайте личный ключ</h1>
        <p className="intro">Фраза не отправляется на сервер. Ключ восстановления личности показывается один раз.</p>
        {error && <div className="banner bad">{error}</div>}
        <label className="field">
          <span>Парольная фраза</span>
          <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete="new-password" required />
        </label>
        <label className="field">
          <span>Повтор</span>
          <input type="password" value={again} onChange={(event) => setAgain(event.target.value)} autoComplete="new-password" required />
        </label>
        {recovery && (
          <>
            <p className="secret-once">{recovery}</p>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={saved} onChange={(event) => setSaved(event.target.checked)} /> Я сохранил ключ восстановления личности
            </label>
          </>
        )}
        <button className="btn primary" disabled={busy || (recovery !== "" && !saved)}>
          {busy ? "Считаем ключ…" : recovery ? "Отправить ключ на подтверждение" : "Создать ключ"}
        </button>
      </form>
    </div>
  );
}

function Pending({ user, onDone }: { user: SessionUser; onDone: () => Promise<void> }) {
  const [error, setError] = useState("");
  return (
    <div className="auth-wrap">
      <div className="auth-card grid gap-4">
        <p className="eyebrow">Подтверждение</p>
        <h1>Ключ ждёт администратора</h1>
        <p className="intro">Пока ключ не подтверждён, реестр закрыт. Если вы единственный администратор, подтвердите свой ключ.</p>
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
            Подтвердить свой ключ
          </button>
        )}
      </div>
    </div>
  );
}
