import { useEffect, useState } from "react";
import { api, explain } from "./api";
import type { PublicKey } from "./types";

type UserRow = { id: string; email: string; display_name: string; role: string; status: string };
type Flag = { id: string; reason: string; flagged_at: string };
type Audit = { id: number; action: string; created_at: string; target_type: string };

export function TeamPage({ selfId }: { selfId: string }) {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [keys, setKeys] = useState<PublicKey[]>([]);
  const [flags, setFlags] = useState<Flag[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [issuer, setIssuer] = useState("");
  const [subject, setSubject] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");

  async function reload() {
    const [userRows, keyRows, flagRows, auditRows] = await Promise.all([
      api<{ users: UserRow[] }>("/api/v1/users"),
      api<{ keys: PublicKey[] }>("/api/v1/crypto/keys"),
      api<{ flags: Flag[] }>("/api/v1/flags"),
      api<{ events: Audit[] }>("/api/v1/audit"),
    ]);
    setUsers(userRows.users);
    setKeys(keyRows.keys);
    setFlags(flagRows.flags);
    setAudit(auditRows.events.slice(0, 30));
  }

  useEffect(() => {
    reload().catch((err) => setError(explain(err)));
  }, []);

  async function run(action: () => Promise<void>) {
    setError("");
    try {
      await action();
      await reload();
    } catch (err) {
      setError(explain(err));
    }
  }

  return (
    <div className="content">
      <p className="eyebrow">Команда</p>
      <h1>Люди и приглашения</h1>
      <p className="intro">Регистрации нет. Приглашение живёт 24 часа, срабатывает один раз и привязано к issuer и subject в Authentik.</p>
      {error && <div className="banner bad">{error}</div>}
      {token && (
        <div className="banner">
          Токен показывается один раз. Передайте его человеку лично.
          <p className="secret-once">{token}</p>
        </div>
      )}
      <form
        className="auth-card grid gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          run(async () => {
            const created = await api<{ token: string }>("/api/v1/invitations", "POST", { issuer, subject, email, role });
            setToken(created.token);
            setSubject("");
            setEmail("");
          });
        }}
      >
        <h2>Приглашение</h2>
        <label className="field">
          <span>Issuer</span>
          <input value={issuer} onChange={(event) => setIssuer(event.target.value)} required placeholder="https://authentik.example/application/o/boris/" />
        </label>
        <label className="field">
          <span>Subject</span>
          <input value={subject} onChange={(event) => setSubject(event.target.value)} required />
        </label>
        <label className="field">
          <span>Почта для карточки</span>
          <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
        </label>
        <label className="field">
          <span>Роль</span>
          <select value={role} onChange={(event) => setRole(event.target.value)}>
            <option value="admin">Администратор</option>
            <option value="manager">Менеджер</option>
            <option value="member">Участник</option>
            <option value="readonly">Только просмотр</option>
          </select>
        </label>
        <button className="btn primary">Создать приглашение</button>
      </form>
      <div className="accounts" style={{ marginTop: 18 }}>
        {users.map((user) => (
          <article key={user.id} className="account">
            <div className="account-top">
              <div>
                <strong>{user.display_name}</strong>
                <div className="service-sub">
                  {user.email} · {user.role} · {user.status}
                </div>
              </div>
              {user.id !== selfId && user.status !== "revoked" && (
                <button className="btn subtle danger" onClick={() => run(() => api(`/api/v1/users/${user.id}/revoke`, "POST", {}))}>
                  Отозвать
                </button>
              )}
            </div>
            {user.id !== selfId && user.status === "active" && (
              <label className="field">
                <span>Сменить роль</span>
                <select
                  value={user.role}
                  onChange={(event) => run(() => api(`/api/v1/users/${user.id}/role`, "POST", { role: event.target.value }))}
                >
                  <option value="admin">Администратор</option>
                  <option value="manager">Менеджер</option>
                  <option value="member">Участник</option>
                  <option value="readonly">Только просмотр</option>
                </select>
              </label>
            )}
          </article>
        ))}
      </div>
      <h2 style={{ marginTop: 28 }}>Ключи</h2>
      <div className="accounts">
        {keys.map((key) => (
          <article key={key.user_id} className="account">
            <div className="account-title">
              {key.display_name} · {key.key_status}
            </div>
            <p className="secret-once">{key.fingerprint}</p>
            {key.key_status === "pending" && key.user_id !== selfId && (
              <div className="flex gap-2">
                <button className="btn primary" onClick={() => run(() => api(`/api/v1/crypto/users/${key.user_id}/approve`, "POST", {}))}>
                  Подтвердить
                </button>
                <button className="btn" onClick={() => run(() => api(`/api/v1/crypto/users/${key.user_id}/reject`, "POST", {}))}>
                  Отклонить
                </button>
              </div>
            )}
          </article>
        ))}
        {keys.length === 0 && <p className="modal-hint">Подтверждённых и ожидающих ключей пока нет.</p>}
      </div>
      {flags.length > 0 && (
        <>
          <h2 style={{ marginTop: 28 }}>Флаги доступа</h2>
          {flags.map((flag) => (
            <p key={flag.id} className="banner">
              {flag.reason}
              <button className="btn" onClick={() => run(() => api(`/api/v1/flags/${flag.id}/resolve`, "POST", {}))}>
                Закрыть
              </button>
            </p>
          ))}
        </>
      )}
      <h2 style={{ marginTop: 28 }}>Журнал</h2>
      <div className="accounts">
        {audit.map((event) => (
          <p key={event.id} className="modal-hint">
            {event.created_at} · {event.action} · {event.target_type}
          </p>
        ))}
      </div>
    </div>
  );
}
