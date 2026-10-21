import { useEffect, useMemo, useRef, useState } from "react";
import { api, explain } from "./api";
import { dueLabel } from "./due";
import { categories, currencies, cycles, type Account, type Service, type Subscription, type WorkspaceData } from "./types";

type Props = {
  data: WorkspaceData;
  category: string;
  readOnly: boolean;
  passwords: Record<string, string>;
  canStore: boolean;
  onReload: () => Promise<void>;
  onSavePassword: (account: Account, password: string) => Promise<void>;
  onImport: (file: File) => Promise<void>;
};

export function Workspace({ data, category, readOnly, passwords, canStore, onReload, onSavePassword, onImport }: Props) {
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [order, setOrder] = useState<SortOrder>(savedOrder);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [editing, setEditing] = useState<Service | null | "new">(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const byService = useMemo(() => {
    const accounts = new Map<string, Account[]>();
    for (const account of data.accounts) {
      const list = accounts.get(account.service_id) ?? [];
      list.push(account);
      accounts.set(account.service_id, list);
    }
    const subs = new Map<string, Subscription>();
    for (const sub of data.subscriptions) {
      if (sub.account_id && !subs.has(sub.account_id)) subs.set(sub.account_id, sub);
    }
    return { accounts, subs };
  }, [data]);

  const found = data.services.filter((service) => {
    if (category !== "all" && service.category !== category) return false;
    const accounts = byService.accounts.get(service.id) ?? [];
    const unclear = service.unclear || !service.url;
    if (filter === "unclear" && !unclear) return false;
    if (filter === "due" && !accounts.some((account) => dueOf(byService.subs.get(account.id)).level)) return false;
    const hay = [service.name, service.url, service.description, ...accounts.flatMap((account) => [account.label, account.login_hint, account.notes, account.card_label])]
      .join(" ")
      .toLocaleLowerCase();
    return hay.includes(query.toLocaleLowerCase());
  });
  const shown = sortServices(found, order);

  async function run(action: () => Promise<void>) {
    setError("");
    try {
      await action();
      await onReload();
    } catch (err) {
      setError(explain(err));
    }
  }

  return (
    <>
      <header className="topbar">
        <div className="crumb">
          workspace<span className="sep">/</span>
          <b>services</b>
        </div>
        <div className="top-actions">
          <a className="btn" href="/api/v1/exports/services.csv">
            ↓ CSV
          </a>
          <a className="btn" href="/api/v1/exports/services.xlsx">
            ↓ Excel
          </a>
          <label className="btn">
            Import backup
            <input
              className="sr-only"
              type="file"
              accept="application/json,.json"
              onChange={(event) => {
                const file = event.target.files?.[0];
                event.target.value = "";
                if (!file) return;
                setError("");
                onImport(file).then(
                  () => setNotice("Backup imported. No password was written to the database in plaintext."),
                  (err) => setError(explain(err)),
                );
              }}
            />
          </label>
        </div>
      </header>
      <div className="content">
        <div className="heading">
          <div>
            <h1>{categories.find((item) => item[0] === category)?.[1]}</h1>
            <p className="stat-strip">{statLine(data)}</p>
          </div>
          {!readOnly && (
            <button className="btn primary" onClick={() => setEditing("new")}>
              ＋ Add service
            </button>
          )}
        </div>
        {data.alerts.length > 0 && (
          <div className="banner">
            {data.alerts
              .map((alert) => {
                const service = data.services.find((item) => item.id === alert.service_id);
                return `${service?.name ?? alert.name} due ${alert.due_on} · ${alert.cost} ${alert.currency}`;
              })
              .join("  ·  ")}
          </div>
        )}
        {error && <div className="banner bad">{error}</div>}
        <p className="payment-legend" aria-label="Payment highlighting">
          <span className="warn">4–7 days until payment</span>
          <span className="alert">3 days or less, or overdue</span>
        </p>
        <div className="toolbar">
          <label className="search">
            <span>Search</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="filter by service, host, login" />
          </label>
          <label className="sort-control">
            <span>Sort</span>
            <select
              value={order}
              onChange={(event) => {
                const next = event.target.value as SortOrder;
                setOrder(next);
                try {
                  localStorage.setItem(sortKey, next);
                } catch {
                  // Private windows may refuse storage; the choice lasts this visit.
                }
              }}
            >
              {sortOrders.map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <div className="filters">
            {[
              ["all", "All"],
              ["unclear", "Needs review"],
              ["due", "Due in the next 7 days"],
            ].map(([id, label]) => (
              <button key={id} className={filter === id ? "filter active" : "filter"} onClick={() => setFilter(id)}>
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="ledger">
        <div className="list-head" aria-hidden="true">
          <span>Service</span>
          <span className="num">Accounts</span>
          <span className="num">Cost / mo</span>
          <span>Due</span>
          <span />
        </div>
        <div id="services">
          {shown.length === 0 && <div className="empty-state">No services found. Try another search or filter.</div>}
          {shown.map((service) => {
            const accounts = byService.accounts.get(service.id) ?? [];
            const dueDays = nearestDue(accounts, byService.subs);
            const level = dueDays === null ? "" : dueDays <= 3 ? "danger" : "warning";
            const opened = open[service.id];
            return (
              <section key={service.id} className={`service ${opened ? "open" : ""} ${level ? `due-${level}` : ""}`}>
                <button className="service-toggle" aria-expanded={opened} onClick={() => setOpen({ ...open, [service.id]: !opened })}>
                  <span className="identity">
                    <span className="logo" style={{ ["--logo-bg" as string]: service.logo_bg, ["--logo-fg" as string]: service.logo_fg }}>
                      {service.logo}
                    </span>
                    <span>
                      <span className="service-name">
                        {service.name}
                        {(service.unclear || !service.url) && <span className="tag">Review</span>}
                      </span>
                      <span className="service-sub">{hostOf(service.url) || service.description}</span>
                    </span>
                  </span>
                  <span className="account-count num">{accounts.length}</span>
                  <span className={`monthly num ${money(accounts, byService.subs) ? "" : "empty"}`}>
                    {money(accounts, byService.subs) || "—"}
                  </span>
                  <span className={`due-cell ${level ? "" : "none"}`}>
                    {level ? (
                      <>
                        <span className="glyph" aria-hidden="true">
                          {level === "danger" ? "▲" : "●"}
                        </span>
                        {dueLabel(dueDays ?? 0)}
                      </>
                    ) : (
                      "—"
                    )}
                  </span>
                  <span className="chevron" aria-hidden="true">
                    ›
                  </span>
                </button>
                {opened && (
                  <div className="service-body">
                    <div className="service-tools">
                      <div>
                        {service.url ? (
                          <a className="btn" href={service.url} target="_blank" rel="noopener noreferrer">
                            Open site ↗
                          </a>
                        ) : (
                          <span className="modal-hint">Name and site need review</span>
                        )}
                      </div>
                      {!readOnly && (
                        <div className="service-tools-right">
                          <button className="btn subtle" onClick={() => setEditing(service)}>
                            Edit service
                          </button>
                          <button className="btn subtle danger" onClick={() => run(() => api(`/api/v1/services/${service.id}/archive`, "POST", {}))}>
                            Archive
                          </button>
                        </div>
                      )}
                    </div>
                    <div className="accounts">
                      {accounts.map((account, index) => (
                        <AccountEditor
                          key={account.id}
                          index={index}
                          account={account}
                          sub={byService.subs.get(account.id)}
                          password={account.vault_item_id ? passwords[account.vault_item_id] ?? "" : ""}
                          readOnly={readOnly}
                          canStore={canStore}
                          onSave={async (body, password) => {
                            await api(`/api/v1/accounts/${account.id}`, "PATCH", body);
                            if (password !== (account.vault_item_id ? passwords[account.vault_item_id] ?? "" : "")) {
                              await onSavePassword(account, password);
                            }
                            await onReload();
                            setNotice("Account saved.");
                          }}
                          onDelete={() => run(() => api(`/api/v1/accounts/${account.id}`, "DELETE", {}))}
                        />
                      ))}
                    </div>
                    {!readOnly && (
                      <button className="add-account" onClick={() => run(() => api(`/api/v1/services/${service.id}/accounts`, "POST", { label: `Account ${accounts.length + 1}` }))}>
                        ＋ Add account
                      </button>
                    )}
                  </div>
                )}
              </section>
            );
          })}
        </div>
        </div>
        <footer className="bottom">
          <span>
            Showing {found.length} of {data.services.length} services
          </span>
          <StatusLine text={notice || "exports never contain passwords"} />
        </footer>
      </div>
      {editing && (
        <ServiceDialog
          service={editing === "new" ? null : editing}
          category={category}
          onClose={() => setEditing(null)}
          onSave={async (body) => {
            if (editing === "new") await api("/api/v1/services", "POST", body);
            else await api(`/api/v1/services/${editing.id}`, "PATCH", body);
            setEditing(null);
            await onReload();
          }}
        />
      )}
    </>
  );
}

export function CategoryNav(props: {
  category: string;
  services: Service[];
  accounts: Account[];
  subscriptions: Subscription[];
  onPick: (id: string) => void;
}) {
  const accounts = new Map<string, Account[]>();
  for (const account of props.accounts) {
    const list = accounts.get(account.service_id) ?? [];
    list.push(account);
    accounts.set(account.service_id, list);
  }
  const subs = new Map<string, Subscription>();
  for (const sub of props.subscriptions) {
    if (sub.account_id) subs.set(sub.account_id, sub);
  }
  return (
    <nav className="nav" aria-label="Categories">
      {categories.map(([id, label, symbol]) => {
        const rows = id === "all" ? props.services : props.services.filter((service) => service.category === id);
        const due = nearestDue(rows.flatMap((service) => accounts.get(service.id) ?? []), subs);
        const level = due === null ? "" : due <= 3 ? "danger" : "warning";
        return (
          <button key={id} className={`${props.category === id ? "active" : ""} ${level ? `due-${level}` : ""}`} onClick={() => props.onPick(id)}>
            <span className="nav-symbol">{symbol}</span>
            {label}
            <span className="count">{rows.length}</span>
          </button>
        );
      })}
    </nav>
  );
}

// statLine is the one-line summary under the title. Numbers, not tiles.
type SortOrder = "az" | "za" | "newest" | "oldest";

const sortOrders: [SortOrder, string][] = [
  ["az", "Name A–Z"],
  ["za", "Name Z–A"],
  ["newest", "Newest first"],
  ["oldest", "Oldest first"],
];

const sortKey = "be.services.sort";

function savedOrder(): SortOrder {
  try {
    const value = localStorage.getItem(sortKey);
    if (sortOrders.some(([id]) => id === value)) return value as SortOrder;
  } catch {
    // Storage can be blocked; fall back to the default.
  }
  return "az";
}

// Names compare the way people read them: case and accents ignored, numbers
// by value, so "Server 2" comes before "Server 10".
const byName = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });

export function sortServices(services: Service[], order: SortOrder): Service[] {
  const sorted = [...services];
  if (order === "az" || order === "za") {
    const direction = order === "za" ? -1 : 1;
    sorted.sort((a, b) => direction * byName.compare(a.name, b.name) || a.id.localeCompare(b.id));
  } else {
    const direction = order === "newest" ? -1 : 1;
    sorted.sort((a, b) => direction * (Date.parse(a.created_at) - Date.parse(b.created_at)) || byName.compare(a.name, b.name));
  }
  return sorted;
}

function statLine(data: WorkspaceData): string {
  const parts = [`${data.summary.services} services`, `${data.summary.accounts} accounts`];
  for (const [currency, amount] of Object.entries(data.summary.monthly)) {
    parts.push(`${amount} ${currency}/mo`);
  }
  if (data.summary.due_soon + data.summary.overdue > 0) parts.push(`${data.summary.due_soon + data.summary.overdue} due soon`);
  if (data.summary.unclear > 0) parts.push(`${data.summary.unclear} need review`);
  return parts.join("  ·  ");
}

// StatusLine is the terminal-style footer. Its cursor blinks briefly after a change.
export function StatusLine({ text }: { text: string }) {
  const [fresh, setFresh] = useState(false);
  useEffect(() => {
    setFresh(true);
    const timer = window.setTimeout(() => setFresh(false), 2000);
    return () => window.clearTimeout(timer);
  }, [text]);
  return (
    <p className={`status-line ${fresh ? "fresh" : ""}`} role="status" aria-live="polite">
      &gt; {text}
      <span className="cursor" aria-hidden="true" />
    </p>
  );
}

function dueOf(sub: Subscription | undefined): { level: string; days: number | null } {
  if (!sub || (sub.due_level !== "warning" && sub.due_level !== "danger")) return { level: "", days: null };
  return { level: sub.due_level, days: sub.days };
}

function nearestDue(accounts: Account[], subs: Map<string, Subscription>): number | null {
  let best: number | null = null;
  for (const account of accounts) {
    const due = dueOf(subs.get(account.id));
    if (due.days === null) continue;
    if (best === null || due.days < best) best = due.days;
  }
  return best;
}

function money(accounts: Account[], subs: Map<string, Subscription>): string {
  const sums: Record<string, number> = {};
  for (const account of accounts) {
    const sub = subs.get(account.id);
    if (!sub) continue;
    const amount = Number(sub.monthly);
    if (!Number.isFinite(amount)) continue;
    sums[sub.currency] = (sums[sub.currency] ?? 0) + amount;
  }
  return Object.entries(sums)
    .map(([currency, amount]) => `${new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(amount)} ${currency}`)
    .join("\n");
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function AccountEditor({
  account,
  sub,
  index,
  password,
  readOnly,
  canStore,
  onSave,
  onDelete,
}: {
  account: Account;
  sub?: Subscription;
  index: number;
  password: string;
  readOnly: boolean;
  canStore: boolean;
  onSave: (body: Record<string, unknown>, password: string) => Promise<void>;
  onDelete: () => void;
}) {
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");
  const due = dueOf(sub);
  return (
    <article className={`account ${due.level ? `due-${due.level}` : ""}`}>
      <form
        className="grid gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          const cycle = String(form.get("billing_cycle") ?? "monthly");
          const custom = Number(form.get("custom_interval_days") ?? 0);
          setError("");
          onSave(
            {
              label: String(form.get("label") ?? ""),
              login_hint: String(form.get("login_hint") ?? ""),
              card_label: String(form.get("card_label") ?? ""),
              notes: String(form.get("notes") ?? ""),
              billing_cycle: cycle,
              renewal_date: String(form.get("renewal_date") ?? ""),
              cost: String(form.get("cost") ?? ""),
              currency: String(form.get("currency") ?? "USD"),
              custom_interval_days: cycle === "custom" ? custom : undefined,
            },
            String(form.get("password") ?? ""),
          ).catch((err) => setError(explain(err)));
        }}
      >
        <div className="account-top">
          <div className="account-title">
            <span className="account-number">{String(index + 1).padStart(2, "0")}</span>
            <input className="account-label" name="label" aria-label={`Account name ${index + 1}`} defaultValue={account.label} maxLength={80} disabled={readOnly} />
          </div>
          {!readOnly && (
            <button type="button" className="btn subtle danger" onClick={onDelete}>
              Delete
            </button>
          )}
        </div>
        <div className="fields">
          <label className="field">
            <span>Login / email</span>
            <input name="login_hint" defaultValue={account.login_hint} placeholder="Enter a login or email" disabled={readOnly} autoComplete="off" />
          </label>
          <label className="field">
            <span>Password / access link</span>
            <span className="password">
              <input name="password" type={show ? "text" : "password"} defaultValue={password} placeholder={canStore ? "Enter a password" : "Unlock the vault first"} disabled={readOnly || !canStore} autoComplete="new-password" />
              <button type="button" onClick={() => setShow(!show)}>
                {show ? "Hide" : "Show"}
              </button>
            </span>
          </label>
          <label className="field">
            <span>Payment method / card</span>
            <input name="card_label" defaultValue={account.card_label} placeholder="Card name, last 4 digits" disabled={readOnly} />
          </label>
          <label className="field">
            <span>Cost</span>
            <span className="cost">
              <input name="cost" defaultValue={sub?.cost ?? ""} inputMode="decimal" placeholder="0.00" disabled={readOnly} />
              <select name="currency" defaultValue={sub?.currency ?? "USD"} aria-label="Currency" disabled={readOnly}>
                {currencies.map((currency) => (
                  <option key={currency}>{currency}</option>
                ))}
              </select>
            </span>
          </label>
          <label className="field">
            <span>Billing cycle</span>
            <select name="billing_cycle" defaultValue={sub?.billing_cycle ?? "monthly"} disabled={readOnly}>
              {cycles.map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Next payment date</span>
            <input name="renewal_date" type="date" defaultValue={sub?.renewal_date ?? ""} disabled={readOnly} />
            {due.level && <small className={`date-hint due-${due.level}`}>{dueLabel(due.days ?? 0)}</small>}
          </label>
          <label className="field">
            <span>Custom interval, days</span>
            <input name="custom_interval_days" type="number" min={1} defaultValue={sub?.custom_interval_days ?? ""} disabled={readOnly} />
          </label>
          <label className="field notes">
            <span>Notes</span>
            <input name="notes" defaultValue={account.notes} placeholder="Plan, owner, comment" disabled={readOnly} />
          </label>
        </div>
        {!readOnly && (
          <div className="modal-actions">
            <button className="btn primary" type="submit">
              Save account
            </button>
          </div>
        )}
        {error && <p className="import-error">{error}</p>}
        {!canStore && <p className="modal-hint">Passwords are not sent until the vault is unlocked and recovery is set up.</p>}
      </form>
    </article>
  );
}

function ServiceDialog({
  service,
  category,
  onClose,
  onSave,
}: {
  service: Service | null;
  category: string;
  onClose: () => void;
  onSave: (body: Record<string, unknown>) => Promise<void>;
}) {
  const [error, setError] = useState("");
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  return (
    <dialog ref={dialog} className="grid" onClose={onClose}>
      <form
        className="grid gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setError("");
          onSave({
            name: String(form.get("name") ?? ""),
            url: String(form.get("url") ?? ""),
            category: String(form.get("category") ?? "other"),
            description: String(form.get("description") ?? ""),
            unclear: form.get("unclear") === "on",
          }).catch((err) => setError(explain(err)));
        }}
      >
        <h2>{service ? "Service settings" : "New service"}</h2>
        <label className="field">
          <span>Name</span>
          <input name="name" required maxLength={160} defaultValue={service?.name ?? ""} placeholder="For example, ChatGPT" />
        </label>
        <label className="field">
          <span>Website</span>
          <input name="url" type="url" defaultValue={service?.url ?? ""} placeholder="https://example.com" />
        </label>
        <label className="field">
          <span>Category</span>
          <select name="category" defaultValue={service?.category ?? (category === "all" ? "tools" : category)}>
            {categories.slice(1).map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Service note</span>
          <input name="description" maxLength={200} defaultValue={service?.description ?? ""} />
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input name="unclear" type="checkbox" defaultChecked={service?.unclear ?? false} /> Needs review
        </label>
        {error && <p className="import-error">{error}</p>}
        <div className="modal-actions">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" type="submit">
            Save
          </button>
        </div>
      </form>
    </dialog>
  );
}
