import { useEffect, useState } from "react";
import { ApiError, api, explain } from "./api";
import {
  enrollRecovery,
  ensureVault,
  loadPasswords,
  myShare,
  newVaultKey,
  readVaultKey,
  rotateVault,
  unlockIdentity,
  unlockWithRecoveryKey,
  writeOwnerEnvelope,
  type HeldKeys,
} from "./crypto/session";
import type { PublicKey, VaultInfo } from "./types";

export type OpenVault = {
  keys: HeldKeys;
  vault: VaultInfo;
  vaultKey: Uint8Array;
  passwords: Record<string, string>;
};

type Props = {
  userId: string;
  recoveryReady: boolean;
  open: OpenVault | null;
  onOpen: (next: OpenVault | null) => void;
  onChanged: () => Promise<void>;
};

export function VaultPage({ userId, recoveryReady, open, onOpen, onChanged }: Props) {
  const [passphrase, setPassphrase] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [keys, setKeys] = useState<PublicKey[]>([]);
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const [shareText, setShareText] = useState("");
  const [share1, setShare1] = useState("");
  const [share2, setShare2] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ keys: PublicKey[] }>("/api/v1/crypto/keys")
      .then((row) => setKeys(row.keys.filter((item) => item.key_status === "approved" && item.user_status === "active")))
      .catch(() => setKeys([]));
  }, [recoveryReady]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (err) {
      setError(explain(err));
    } finally {
      setBusy(false);
    }
  }

  async function finishUnlock(held: HeldKeys) {
    const vault = await ensureVault();
    let vaultKey: Uint8Array;
    try {
      vaultKey = await readVaultKey(held, vault.id, vault.key_version);
    } catch (err) {
      if (!(err instanceof ApiError) || err.status !== 404) throw err;
      vaultKey = await newVaultKey();
      await writeOwnerEnvelope(held, userId, vault.id, vault.key_version, vaultKey);
    }
    const passwords = recoveryReady ? await loadPasswords(vault, vaultKey) : {};
    onOpen({ keys: held, vault, vaultKey, passwords });
    setNotice(recoveryReady ? "Сейф открыт." : "Личный ключ открыт. Назначьте двух хранителей, чтобы записывать пароли.");
  }

  return (
    <div className="content">
      <p className="eyebrow">Сейф</p>
      <h1>Ключи команды</h1>
      <p className="intro">Сервер хранит только зашифрованные конверты. Парольная фраза и личный ключ не покидают браузер.</p>
      {error && <div className="banner bad">{error}</div>}
      {notice && <p className="modal-hint">{notice}</p>}
      {!open && (
        <form
          className="auth-card grid gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            const phrase = passphrase;
            const savedRecovery = recoveryKey;
            setPassphrase("");
            setRecoveryKey("");
            run(async () => {
              const held = useRecovery ? await unlockWithRecoveryKey(savedRecovery) : await unlockIdentity(phrase);
              await finishUnlock(held);
            });
          }}
        >
          {useRecovery ? (
            <label className="field">
              <span>Ключ восстановления</span>
              <textarea value={recoveryKey} onChange={(event) => setRecoveryKey(event.target.value)} rows={3} autoComplete="off" required />
            </label>
          ) : (
            <label className="field">
              <span>Парольная фраза</span>
              <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete="current-password" required />
            </label>
          )}
          <button className="btn primary" disabled={busy}>
            {busy ? "Открываем…" : "Открыть сейф"}
          </button>
          <button
            className="btn"
            type="button"
            onClick={() => {
              setUseRecovery((current) => !current);
              setError("");
            }}
          >
            {useRecovery ? "Открыть парольной фразой" : "Открыть ключом восстановления"}
          </button>
          {useRecovery && <p className="modal-hint">Сброс пароля в Authentik этот ключ не заменяет. Ключ показывался один раз при создании.</p>}
        </form>
      )}
      {open && (
        <div className="grid gap-4">
          <p className="modal-hint">
            Сейф «{open.vault.name}», версия ключа {open.vault.key_version}. {recoveryReady ? "Восстановление готово." : "Восстановление ещё не назначено."}
            {open.vault.rotation_required ? " Нужна смена ключа: у кого-то сменился публичный ключ." : ""}
          </p>
          {!recoveryReady && (
            <form
              className="auth-card grid gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                const a = keys.find((item) => item.user_id === first);
                const b = keys.find((item) => item.user_id === second);
                if (!a || !b) {
                  setError("Выберите двух разных участников с подтверждённым ключом.");
                  return;
                }
                run(async () => {
                  await enrollRecovery(a, b, open.vault, open.vaultKey);
                  setNotice("Две доли восстановления запечатаны. Пароли можно сохранять.");
                  await onChanged();
                });
              }}
            >
              <h2>Два хранителя</h2>
              <p className="modal-hint">Каждый получит одну долю. Вместе они восстанавливают ключ сейфа. По одной доле этого сделать нельзя.</p>
              <label className="field">
                <span>Хранитель 1</span>
                <select value={first} onChange={(event) => setFirst(event.target.value)} required>
                  <option value="">Выберите</option>
                  {keys.map((item) => (
                    <option key={item.user_id} value={item.user_id}>
                      {item.display_name} · {item.email}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Хранитель 2</span>
                <select value={second} onChange={(event) => setSecond(event.target.value)} required>
                  <option value="">Выберите</option>
                  {keys.map((item) => (
                    <option key={item.user_id} value={item.user_id}>
                      {item.display_name} · {item.email}
                    </option>
                  ))}
                </select>
              </label>
              <button className="btn primary" disabled={busy || keys.length < 2}>
                {keys.length < 2 ? "Нужен второй участник с ключом" : "Назначить хранителей"}
              </button>
            </form>
          )}
          <div className="flex gap-2">
            <button
              className="btn"
              onClick={() =>
                run(async () => {
                  setShareText(await myShare(open.keys));
                })
              }
            >
              Показать мою долю
            </button>
            <button
              className="btn danger"
              onClick={() => {
                onOpen(null);
                setShareText("");
                setNotice("Сейф закрыт в этой вкладке.");
              }}
            >
              Закрыть сейф
            </button>
          </div>
          {shareText && (
            <div>
              <p className="modal-hint">Это секрет. Передайте его второму хранителю только когда вы вместе восстанавливаете сейф.</p>
              <p className="secret-once">{shareText}</p>
            </div>
          )}
          <form
            className="auth-card grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              run(async () => {
                const next = await rotateVault(open.vault, open.vaultKey, share1.trim(), share2.trim());
                const passwords = await loadPasswords({ ...open.vault, key_version: next.keyVersion }, next.vaultKey);
                onOpen({ ...open, vault: { ...open.vault, key_version: next.keyVersion, rotation_required: false }, vaultKey: next.vaultKey, passwords });
                setShare1("");
                setShare2("");
                setNotice("Ключ сейфа сменён. Старые конверты удалены.");
                await onChanged();
              });
            }}
          >
            <h2>Сменить ключ сейфа</h2>
            <p className="modal-hint">Нужны обе доли восстановления. Они снова запечатывают новый ключ и не отправляются открытыми.</p>
            <label className="field">
              <span>Доля 1</span>
              <textarea value={share1} onChange={(event) => setShare1(event.target.value)} rows={3} />
            </label>
            <label className="field">
              <span>Доля 2</span>
              <textarea value={share2} onChange={(event) => setShare2(event.target.value)} rows={3} />
            </label>
            <button className="btn primary" disabled={busy}>
              Сменить ключ
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
