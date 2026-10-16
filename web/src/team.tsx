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
      <h1>People and invitations</h1>
      <p className="intro">There is no self-registration. An invitation lasts 24 hours, works once, and is bound to an Authentik issuer and subject.</p>
      {error && <div className="banner bad">{error}</div>}
      {token && (
        <div className="banner">
          The token is shown once. Hand it to the person directly.
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
        <h2>Invitation</h2>
        <label className="field">
          <span>Issuer</span>
          <input value={issuer} onChange={(event) => setIssuer(event.target.value)} required placeholder="https://authentik.example/application/o/boris/" />
        </label>
        <label className="field">
          <span>Subject</span>
          <input value={subject} onChange={(event) => setSubject(event.target.value)} required />
        </label>
        <label className="field">
          <span>Email for the profile</span>
          <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
        </label>
        <label className="field">
          <span>Role</span>
          <select value={role} onChange={(event) => setRole(event.target.value)}>
            <option value="admin">Admin</option>
            <option value="manager">Manager</option>
            <option value="member">Member</option>
            <option value="readonly">Read-only</option>
          </select>
        </label>
        <button className="btn primary">Create invitation</button>
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
                  Revoke
                </button>
              )}
            </div>
            {user.id !== selfId && user.status === "active" && (
              <label className="field">
                <span>Change role</span>
                <select
                  value={user.role}
                  onChange={(event) => run(() => api(`/api/v1/users/${user.id}/role`, "POST", { role: event.target.value }))}
                >
                  <option value="admin">Admin</option>
                  <option value="manager">Manager</option>
                  <option value="member">Member</option>
                  <option value="readonly">Read-only</option>
                </select>
              </label>
            )}
          </article>
        ))}
      </div>
      <h2 style={{ marginTop: 28 }}>Keys</h2>
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
                  Approve
                </button>
                <button className="btn" onClick={() => run(() => api(`/api/v1/crypto/users/${key.user_id}/reject`, "POST", {}))}>
                  Reject
                </button>
              </div>
            )}
          </article>
        ))}
        {keys.length === 0 && <p className="modal-hint">No approved or pending keys yet.</p>}
      </div>
      {flags.length > 0 && (
        <>
          <h2 style={{ marginTop: 28 }}>Access flags</h2>
          {flags.map((flag) => (
            <p key={flag.id} className="banner">
              {flag.reason}
              <button className="btn" onClick={() => run(() => api(`/api/v1/flags/${flag.id}/resolve`, "POST", {}))}>
                Dismiss
              </button>
            </p>
          ))}
        </>
      )}
      <h2 style={{ marginTop: 28 }}>Audit log</h2>
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
