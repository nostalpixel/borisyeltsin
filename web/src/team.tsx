import { useEffect, useState } from "react";
import { api, explain } from "./api";
import { pinKey, pinState } from "./crypto/pins";
import type { PublicKey } from "./types";
import { PinBadge, VerifyKeyDialog } from "./verify";
import { StatusLine } from "./workspace";

type UserRow = { id: string; email: string; display_name: string; role: string; status: string };
type Flag = { id: string; reason: string; flagged_at: string };
type Audit = { id: number; action: string; created_at: string; target_type: string };
type Invitation = { id: string; email: string; issuer: string; subject: string; role: string; expires_at: string; accepted: boolean; revoked: boolean };
type Proposal = { user_id: string; display_name: string; email: string; fingerprint: string; public_key: string; created_at: string };
type Tab = "people" | "invitations" | "keys" | "audit";

// Review is a pending verify-then-approve dialog.
type Review = { key: PublicKey; replacement: boolean };

const roles: [string, string][] = [
  ["admin", "Admin"],
  ["manager", "Manager"],
  ["member", "Member"],
  ["readonly", "Read-only"],
];

export function TeamPage({ selfId }: { selfId: string }) {
  const [tab, setTab] = useState<Tab>("people");
  const [users, setUsers] = useState<UserRow[]>([]);
  const [keys, setKeys] = useState<PublicKey[]>([]);
  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [flags, setFlags] = useState<Flag[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [review, setReview] = useState<Review | null>(null);

  async function reload() {
    const [userRows, keyRows, proposalRows, inviteRows, flagRows, auditRows] = await Promise.all([
      api<{ users: UserRow[] }>("/api/v1/users"),
      api<{ keys: PublicKey[] }>("/api/v1/crypto/keys"),
      api<{ proposals: Proposal[] }>("/api/v1/crypto/proposals"),
      api<{ invitations: Invitation[] }>("/api/v1/invitations"),
      api<{ flags: Flag[] }>("/api/v1/flags"),
      api<{ events: Audit[] }>("/api/v1/audit"),
    ]);
    setUsers(userRows.users);
    setKeys(keyRows.keys);
    setProposals(proposalRows.proposals);
    setInvitations(inviteRows.invitations);
    setFlags(flagRows.flags);
    setAudit(auditRows.events.slice(0, 50));
  }

  useEffect(() => {
    reload().catch((err) => setError(explain(err)));
  }, []);

  async function run(action: () => Promise<void>, done?: string) {
    setError("");
    try {
      await action();
      await reload();
      if (done) setNotice(done);
    } catch (err) {
      setError(explain(err));
    }
  }

  const waiting = keys.filter((key) => key.key_status === "pending" && key.user_id !== selfId).length + proposals.length;
  const open = invitations.filter((invite) => !invite.accepted && !invite.revoked && new Date(invite.expires_at) > new Date()).length;

  return (
    <div className="content">
      <h1>Team</h1>
      <p className="stat-strip">{`${users.filter((user) => user.status === "active").length} active  ·  ${open} open invitations  ·  ${waiting} keys waiting`}</p>
      {error && <div className="banner bad">{error}</div>}
      <div className="tabs" role="tablist" aria-label="Team">
        {(
          [
            ["people", "People"],
            ["invitations", "Invitations"],
            ["keys", waiting ? `Keys (${waiting})` : "Keys"],
            ["audit", "Audit"],
          ] as [Tab, string][]
        ).map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "tab active" : "tab"} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      <section role="tabpanel">
        {tab === "people" && (
          <>
            {flags.map((flag) => (
              <div key={flag.id} className="banner">
                Change the passwords this person could see ({flag.reason.replace("_", " ")}, {flag.flagged_at.slice(0, 10)}).{" "}
                <button className="text-button" onClick={() => run(() => api(`/api/v1/flags/${flag.id}/resolve`, "POST", {}))}>
                  Done
                </button>
              </div>
            ))}
            <div className="data-table">
              <div className="data-head" aria-hidden="true">
                <span>Person</span>
                <span>Role</span>
                <span>Status</span>
                <span />
              </div>
              {users.map((user) => (
                <div key={user.id} className="data-row">
                  <span>
                    <span className="service-name">{user.display_name}</span>
                    <span className="service-sub">{user.email}</span>
                  </span>
                  <span>
                    {user.id !== selfId && user.status === "active" ? (
                      <select
                        className="inline-select"
                        aria-label={`Role of ${user.email}`}
                        value={user.role}
                        onChange={(event) => run(() => api(`/api/v1/users/${user.id}/role`, "POST", { role: event.target.value }), "role changed")}
                      >
                        {roles.map(([id, label]) => (
                          <option key={id} value={id}>
                            {label}
                          </option>
                        ))}
                      </select>
                    ) : (
                      user.role
                    )}
                  </span>
                  <span className={user.status === "revoked" ? "alert-text" : user.status === "active" ? "" : "warn-text"}>{user.status.replace("_", " ")}</span>
                  <span className="row-actions">
                    {user.id !== selfId && user.status !== "revoked" && (
                      <button
                        className="btn subtle danger"
                        onClick={() =>
                          run(() => api(`/api/v1/users/${user.id}/revoke`, "POST", {}), `${user.email} revoked; rotate the vault key in Vault › Recovery`)
                        }
                      >
                        Revoke
                      </button>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}

        {tab === "invitations" && (
          <InvitationsTab
            invitations={invitations}
            token={token}
            onCreate={(body) =>
              run(async () => {
                const created = await api<{ token: string }>("/api/v1/invitations", "POST", body);
                setToken(created.token);
              }, "invitation created; the key is shown once")
            }
            onRevoke={(id) => run(() => api(`/api/v1/invitations/${id}/revoke`, "POST", {}), "invitation revoked")}
            onDismissToken={() => setToken("")}
          />
        )}

        {tab === "keys" && (
          <div className="data-table">
            <div className="data-head" aria-hidden="true">
              <span>Person</span>
              <span>Key</span>
              <span>Verified here</span>
              <span />
            </div>
            {keys.length === 0 && proposals.length === 0 && <p className="empty-state">Nothing waiting.</p>}
            {proposals.map((proposal) => {
              const key: PublicKey = { ...proposal, user_status: "active", key_status: "proposed" };
              return (
                <div key={`p-${proposal.user_id}`} className="data-row">
                  <span>
                    <span className="service-name">{proposal.display_name}</span>
                    <span className="service-sub">{proposal.email}</span>
                  </span>
                  <span className="warn-text">● replacement key</span>
                  <PinBadge viewerId={selfId} userId={proposal.user_id} fingerprint={proposal.fingerprint} />
                  <span className="row-actions">
                    <button className="btn" onClick={() => setReview({ key, replacement: true })}>
                      Verify and approve
                    </button>
                    <button className="btn subtle danger" onClick={() => run(() => api(`/api/v1/crypto/users/${proposal.user_id}/reject`, "POST", {}), "replacement rejected")}>
                      Reject
                    </button>
                  </span>
                </div>
              );
            })}
            {keys.map((key) => (
              <div key={key.user_id} className="data-row">
                <span>
                  <span className="service-name">{key.display_name}</span>
                  <span className="service-sub">{key.email}</span>
                </span>
                <span className={key.key_status === "pending" ? "warn-text" : key.key_status === "rejected" ? "alert-text" : ""}>
                  {key.key_status === "pending" ? "● waiting for approval" : key.key_status}
                </span>
                {key.user_id === selfId ? <span className="ok-text">✓ you</span> : <PinBadge viewerId={selfId} userId={key.user_id} fingerprint={key.fingerprint} />}
                <span className="row-actions">
                  {key.key_status === "pending" && key.user_id !== selfId && (
                    <>
                      <button className="btn" onClick={() => setReview({ key, replacement: false })}>
                        Verify and approve
                      </button>
                      <button className="btn subtle danger" onClick={() => run(() => api(`/api/v1/crypto/users/${key.user_id}/reject`, "POST", {}), "key rejected")}>
                        Reject
                      </button>
                    </>
                  )}
                  {key.key_status === "approved" && key.user_id !== selfId && pinState(selfId, key.user_id, key.fingerprint).state !== "verified" && (
                    <button className="btn subtle" onClick={() => setReview({ key, replacement: false })}>
                      Verify
                    </button>
                  )}
                </span>
              </div>
            ))}
          </div>
        )}

        {tab === "audit" && (
          <div className="data-table">
            <div className="data-head audit" aria-hidden="true">
              <span>Time</span>
              <span>Action</span>
              <span>Target</span>
            </div>
            {audit.length === 0 && <p className="empty-state">No events yet.</p>}
            {audit.map((event) => (
              <div key={event.id} className="data-row audit">
                <span>{event.created_at.slice(0, 19).replace("T", " ")}</span>
                <span>{event.action.replaceAll("_", " ")}</span>
                <span>{event.target_type}</span>
              </div>
            ))}
          </div>
        )}
      </section>
      <footer className="bottom">
        <span />
        <StatusLine text={notice || "only invited people can sign in"} />
      </footer>
      {review && (
        <VerifyKeyDialog
          viewerId={selfId}
          userId={review.key.user_id}
          name={review.key.display_name || review.key.email}
          fingerprint={review.key.fingerprint}
          confirmLabel={review.key.key_status === "approved" ? "Fingerprints match" : "Fingerprints match, approve"}
          onConfirm={async () => {
            if (review.key.key_status !== "approved") {
              await api(`/api/v1/crypto/users/${review.key.user_id}/approve`, "POST", {});
            }
            pinKey(selfId, review.key.user_id, review.key.fingerprint);
            await reload();
            setNotice(review.key.key_status === "approved" ? "key verified in this browser" : review.replacement ? "replacement approved" : "key approved");
          }}
          onClose={() => setReview(null)}
        />
      )}
    </div>
  );
}

function InvitationsTab({
  invitations,
  token,
  onCreate,
  onRevoke,
  onDismissToken,
}: {
  invitations: Invitation[];
  token: string;
  onCreate: (body: { issuer: string; subject: string; email: string; role: string }) => void;
  onRevoke: (id: string) => void;
  onDismissToken: () => void;
}) {
  const [issuer, setIssuer] = useState(invitations[0]?.issuer ?? "");
  const [subject, setSubject] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const now = new Date();
  const state = (invite: Invitation) =>
    invite.accepted ? "accepted" : invite.revoked ? "revoked" : new Date(invite.expires_at) <= now ? "expired" : "open";

  return (
    <div className="split">
      <form
        className="panel stack"
        onSubmit={(event) => {
          event.preventDefault();
          onCreate({ issuer, subject, email, role });
          setSubject("");
          setEmail("");
        }}
      >
        <h2>Invite someone</h2>
        <p className="prose">The invitation works once, for 24 hours, and only for this exact Authentik account.</p>
        {token && (
          <div className="stack">
            <figure className="fingerprint">
              <figcaption>Invitation key (shown once)</figcaption>
              <code className="token-box invite-key">{token}</code>
            </figure>
            <p className="prose">Hand it to the person directly, or read it out. They type it on the sign-in page.</p>
            <button type="button" className="btn" onClick={onDismissToken}>
              I handed it over
            </button>
          </div>
        )}
        <label className="field">
          <span>Authentik issuer URL</span>
          <input value={issuer} onChange={(event) => setIssuer(event.target.value)} required placeholder="https://authentik.example/application/o/borisyeltsin/" />
        </label>
        <label className="field">
          <span>Authentik user ID (subject)</span>
          <input value={subject} onChange={(event) => setSubject(event.target.value)} required spellCheck={false} />
        </label>
        <label className="field">
          <span>Email</span>
          <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
        </label>
        <label className="field">
          <span>Role</span>
          <select value={role} onChange={(event) => setRole(event.target.value)}>
            {roles.map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <button className="btn primary">Create invitation</button>
      </form>
      <div className="data-table">
        <div className="data-head" aria-hidden="true">
          <span>Invited</span>
          <span>Role</span>
          <span>State</span>
          <span />
        </div>
        {invitations.length === 0 && <p className="empty-state">No invitations yet.</p>}
        {invitations.map((invite) => {
          const current = state(invite);
          return (
            <div key={invite.id} className="data-row">
              <span>
                <span className="service-name">{invite.email}</span>
                <span className="service-sub">until {invite.expires_at.slice(0, 16).replace("T", " ")}</span>
              </span>
              <span>{invite.role}</span>
              <span className={current === "open" ? "warn-text" : ""}>{current}</span>
              <span className="row-actions">
                {current === "open" && (
                  <button className="btn subtle danger" onClick={() => onRevoke(invite.id)}>
                    Revoke
                  </button>
                )}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
