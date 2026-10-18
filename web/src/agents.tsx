import { useEffect, useState } from "react";
import { api, explain } from "./api";
import { StatusLine } from "./workspace";

type Token = {
  id: string;
  name: string;
  can_write: boolean;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  revoked: boolean;
  mine: boolean;
  owner: { id: string; display_name: string; email: string };
};

const lifetimes: [number, string][] = [
  [7, "7 days"],
  [30, "30 days"],
  [90, "90 days"],
];

// AgentsPage manages personal tokens for the MCP endpoint (docs/MCP.md).
export function AgentsPage({ isAdmin, readOnly }: { isAdmin: boolean; readOnly: boolean }) {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [everyone, setEveryone] = useState(false);
  const [name, setName] = useState("Claude");
  const [days, setDays] = useState(30);
  const [canWrite, setCanWrite] = useState(false);
  const [created, setCreated] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const endpoint = `${window.location.origin}/mcp`;

  async function reload(all = everyone) {
    const rows = await api<{ tokens: Token[] }>(`/api/v1/tokens${all ? "?all=1" : ""}`);
    setTokens(rows.tokens);
  }

  useEffect(() => {
    reload().catch((err) => setError(explain(err)));
  }, [everyone]);

  async function run(action: () => Promise<void>, done: string) {
    setError("");
    try {
      await action();
      await reload();
      setNotice(done);
    } catch (err) {
      setError(explain(err));
    }
  }

  const now = new Date();
  const state = (token: Token) => (token.revoked ? "revoked" : new Date(token.expires_at) <= now ? "expired" : "active");
  const live = tokens.filter((token) => token.mine && state(token) === "active").length;

  return (
    <div className="content">
      <h1>Agents</h1>
      <p className="stat-strip">{`${live} active ${live === 1 ? "token" : "tokens"}  ·  endpoint ${endpoint}`}</p>
      {error && <div className="banner bad">{error}</div>}
      <div className="split">
        <form
          className="panel stack"
          onSubmit={(event) => {
            event.preventDefault();
            run(async () => {
              const result = await api<{ token: string }>("/api/v1/tokens", "POST", { name, days, can_write: canWrite });
              setCreated(result.token);
            }, "token created; it is shown once");
          }}
        >
          <h2>Connect an AI agent</h2>
          <p className="prose">
            A token lets an MCP client such as Claude read the subscription ledger as you: what renews when, and what it costs. It sees only the
            services you can see. It never sees the vault, logins or payment cards.
          </p>
          {created && (
            <div className="stack">
              <figure className="fingerprint">
                <figcaption>Token (shown once)</figcaption>
                <code className="token-box">{created}</code>
              </figure>
              <p className="prose">Add it to Claude Code:</p>
              <code className="token-box">{`claude mcp add --transport http borisyeltsin ${endpoint} --header "Authorization: Bearer ${created}"`}</code>
              <button
                type="button"
                className="btn"
                onClick={() => {
                  navigator.clipboard?.writeText(created).catch(() => undefined);
                  setNotice("token copied");
                }}
              >
                Copy token
              </button>
              <button type="button" className="btn" onClick={() => setCreated("")}>
                I saved it
              </button>
            </div>
          )}
          <label className="field">
            <span>Name</span>
            <input value={name} onChange={(event) => setName(event.target.value)} required maxLength={80} />
          </label>
          <label className="field">
            <span>Expires after</span>
            <select value={days} onChange={(event) => setDays(Number(event.target.value))}>
              {lifetimes.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          {!readOnly && (
            <label className="check">
              <input type="checkbox" checked={canWrite} onChange={(event) => setCanWrite(event.target.checked)} />
              <span>Can also add subscriptions</span>
            </label>
          )}
          <button className="btn primary">Create token</button>
        </form>
        <div className="stack">
          {isAdmin && (
            <label className="check">
              <input type="checkbox" checked={everyone} onChange={(event) => setEveryone(event.target.checked)} />
              <span>Show everyone's tokens</span>
            </label>
          )}
          <div className="data-table">
            <div className="data-head tokens" aria-hidden="true">
              <span>Token</span>
              <span>Access</span>
              <span>State</span>
              <span />
            </div>
            {tokens.length === 0 && <p className="empty-state">No tokens yet.</p>}
            {tokens.map((token) => {
              const current = state(token);
              return (
                <div key={token.id} className="data-row tokens">
                  <span>
                    <span className="service-name">{token.name}</span>
                    <span className="service-sub">
                      {token.mine ? "" : `${token.owner.email} · `}
                      {token.last_used_at ? `used ${token.last_used_at.slice(0, 16).replace("T", " ")}` : "never used"}
                    </span>
                  </span>
                  <span>{token.can_write ? "read, add" : "read"}</span>
                  <span className={current === "active" ? "" : "warn-text"}>
                    {current === "active" ? `until ${token.expires_at.slice(0, 10)}` : current}
                  </span>
                  <span className="row-actions">
                    {current === "active" && (
                      <button className="btn subtle danger" onClick={() => run(() => api(`/api/v1/tokens/${token.id}/revoke`, "POST", {}), "token revoked")}>
                        Revoke
                      </button>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
      <StatusLine text={notice || "agents read the ledger; the vault stays in your browser"} />
    </div>
  );
}
