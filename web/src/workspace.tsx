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
      .toLocaleLowerCase("ru");
    return hay.includes(query.toLocaleLowerCase("ru"));
  });

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
          Рабочее пространство <span style={{ margin: "0 9px", color: "#c2c7d1" }}>/</span>
          <b>Сервисы и оплаты</b>
        </div>
        <div className="top-actions">
          <a className="btn" href="/api/v1/exports/services.csv">
            ↓ CSV
          </a>
          <a className="btn" href="/api/v1/exports/services.xlsx">
            ↓ Excel
          </a>
          <label className="btn">
            Резервная копия
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
                  () => setNotice("Копия импортирована. Пароли не записаны в базу открытым текстом."),
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
            <p className="eyebrow">Аккаунты · Подписки · Платежи</p>
            <h1>{categories.find((item) => item[0] === category)?.[1]}</h1>
            <p className="intro">Откройте сервис, чтобы управлять аккаунтами и оплатами. Пароли живут только в сейфе.</p>
          </div>
          {!readOnly && (
            <button className="btn primary" onClick={() => setEditing("new")}>
              ＋ Добавить сервис
            </button>
          )}
        </div>
        <section className="metrics" aria-label="Обзор">
          <Metric label="Сервисов" value={data.summary.services} />
          <Metric label="Аккаунтов" value={data.summary.accounts} />
          <Metric label="Нужно уточнить" value={data.summary.unclear} amber />
        </section>
        {data.alerts.length > 0 && (
          <div className="banner">
            Напоминания: {data.alerts.map((alert) => `${alert.name} за ${alert.days_before} дн. (${alert.due_on})`).join(" · ")}
          </div>
        )}
        {error && <div className="banner bad">{error}</div>}
        {notice && <p className="modal-hint">{notice}</p>}
        <p className="payment-legend" aria-label="Подсветка оплаты">
          <span>
            <i />
            4–7 дней до оплаты
          </span>
          <span>
            <i className="red" />3 дня и меньше, включая просрочку
          </span>
        </p>
        <div className="toolbar">
          <label className="search">
            <span aria-hidden="true">⌕</span>
            <span className="sr-only">Поиск сервисов и аккаунтов</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Найти сервис или аккаунт…" />
          </label>
          <div className="filters">
            {[
              ["all", "Все"],
              ["unclear", "Требуют уточнения"],
              ["due", "Оплата в ближайшие 7 дней"],
            ].map(([id, label]) => (
              <button key={id} className={filter === id ? "filter active" : "filter"} onClick={() => setFilter(id)}>
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="list-head" aria-hidden="true">
          <span>Сервис</span>
          <span>Аккаунты</span>
          <span>В месяц</span>
          <span />
        </div>
        <div id="services">
          {found.length === 0 && <div className="empty-state">Сервисы не найдены. Попробуйте другой поиск или фильтр.</div>}
          {found.map((service) => {
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
                        {(service.unclear || !service.url) && <span className="tag">Уточнить</span>}
                      </span>
                      <span className="service-sub">
                        {hostOf(service.url) || service.description} · {accounts.length} акк.
                      </span>
                      {level && <span className="due-label">{dueLabel(dueDays ?? 0)}</span>}
                    </span>
                  </span>
                  <span className="account-count">{accounts.length} акк.</span>
                  <span className={`monthly ${money(accounts, byService.subs) ? "" : "empty"}`} style={{ whiteSpace: "pre-line" }}>
                    {money(accounts, byService.subs) || "Добавьте оплату"}
                  </span>
                  <span className="chevron">›</span>
                </button>
                {opened && (
                  <div className="service-body">
                    <div className="service-tools">
                      <div>
                        {service.url ? (
                          <a className="btn" href={service.url} target="_blank" rel="noopener noreferrer">
                            Открыть сайт ↗
                          </a>
                        ) : (
                          <span className="modal-hint">Название и сайт нужно уточнить</span>
                        )}
                      </div>
                      {!readOnly && (
                        <div className="service-tools-right">
                          <button className="btn subtle" onClick={() => setEditing(service)}>
                            Изменить сервис
                          </button>
                          <button className="btn subtle danger" onClick={() => run(() => api(`/api/v1/services/${service.id}/archive`, "POST", {}))}>
                            В архив
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
                            setNotice("Аккаунт сохранён.");
                          }}
                          onDelete={() => run(() => api(`/api/v1/accounts/${account.id}`, "DELETE", {}))}
                        />
                      ))}
                    </div>
                    {!readOnly && (
                      <button className="add-account" onClick={() => run(() => api(`/api/v1/services/${service.id}/accounts`, "POST", { label: `Аккаунт ${accounts.length + 1}` }))}>
                        ＋ Добавить аккаунт
                      </button>
                    )}
                  </div>
                )}
              </section>
            );
          })}
        </div>
        <footer className="bottom">
          <span>
            Показано {found.length} из {data.services.length} сервисов
          </span>
          <span>Excel и CSV не содержат паролей.</span>
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
    <nav className="nav" aria-label="Категории">
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

function Metric({ label, value, amber }: { label: string; value: number; amber?: boolean }) {
  return (
    <div className="metric">
      <div>
        <small>{label}</small>
        <div>
          <strong>{value}</strong>
        </div>
      </div>
      <span className={`metric-icon ${amber ? "amber" : ""}`}>{amber ? "?" : "▦"}</span>
    </div>
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
    .map(([currency, amount]) => `${new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 2 }).format(amount)} ${currency}`)
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
            <input className="account-label" name="label" aria-label={`Название аккаунта ${index + 1}`} defaultValue={account.label} maxLength={80} disabled={readOnly} />
          </div>
          {!readOnly && (
            <button type="button" className="btn subtle danger" onClick={onDelete}>
              Удалить
            </button>
          )}
        </div>
        <div className="fields">
          <label className="field">
            <span>Логин / email</span>
            <input name="login_hint" defaultValue={account.login_hint} placeholder="Введите логин или email" disabled={readOnly} autoComplete="off" />
          </label>
          <label className="field">
            <span>Пароль / ссылка на доступ</span>
            <span className="password">
              <input name="password" type={show ? "text" : "password"} defaultValue={password} placeholder={canStore ? "Введите пароль" : "Сначала откройте сейф"} disabled={readOnly || !canStore} autoComplete="new-password" />
              <button type="button" onClick={() => setShow(!show)}>
                {show ? "Скрыть" : "Показать"}
              </button>
            </span>
          </label>
          <label className="field">
            <span>Способ оплаты / карта</span>
            <input name="card_label" defaultValue={account.card_label} placeholder="Название карты, последние 4 цифры" disabled={readOnly} />
          </label>
          <label className="field">
            <span>Стоимость</span>
            <span className="cost">
              <input name="cost" defaultValue={sub?.cost ?? ""} inputMode="decimal" placeholder="0.00" disabled={readOnly} />
              <select name="currency" defaultValue={sub?.currency ?? "USD"} aria-label="Валюта" disabled={readOnly}>
                {currencies.map((currency) => (
                  <option key={currency}>{currency}</option>
                ))}
              </select>
            </span>
          </label>
          <label className="field">
            <span>Период</span>
            <select name="billing_cycle" defaultValue={sub?.billing_cycle ?? "monthly"} disabled={readOnly}>
              {cycles.map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Ближайшая дата оплаты</span>
            <input name="renewal_date" type="date" defaultValue={sub?.renewal_date ?? ""} disabled={readOnly} />
            {due.level && <small className={`date-hint due-${due.level}`}>{dueLabel(due.days ?? 0)}</small>}
          </label>
          <label className="field">
            <span>Свой интервал, дни</span>
            <input name="custom_interval_days" type="number" min={1} defaultValue={sub?.custom_interval_days ?? ""} disabled={readOnly} />
          </label>
          <label className="field notes">
            <span>Заметки</span>
            <input name="notes" defaultValue={account.notes} placeholder="Тариф, владелец, комментарий" disabled={readOnly} />
          </label>
        </div>
        {!readOnly && (
          <div className="modal-actions">
            <button className="btn primary" type="submit">
              Сохранить аккаунт
            </button>
          </div>
        )}
        {error && <p className="import-error">{error}</p>}
        {!canStore && <p className="modal-hint">Пароль не отправляется на сервер, пока сейф не открыт и не готово восстановление.</p>}
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
        <h2>{service ? "Настройки сервиса" : "Новый сервис"}</h2>
        <label className="field">
          <span>Название</span>
          <input name="name" required maxLength={160} defaultValue={service?.name ?? ""} placeholder="Например, ChatGPT" />
        </label>
        <label className="field">
          <span>Сайт</span>
          <input name="url" type="url" defaultValue={service?.url ?? ""} placeholder="https://example.com" />
        </label>
        <label className="field">
          <span>Категория</span>
          <select name="category" defaultValue={service?.category ?? (category === "all" ? "tools" : category)}>
            {categories.slice(1).map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Заметка о сервисе</span>
          <input name="description" maxLength={200} defaultValue={service?.description ?? ""} />
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input name="unclear" type="checkbox" defaultChecked={service?.unclear ?? false} /> Нужно уточнить
        </label>
        {error && <p className="import-error">{error}</p>}
        <div className="modal-actions">
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button className="btn primary" type="submit">
            Сохранить
          </button>
        </div>
      </form>
    </dialog>
  );
}
