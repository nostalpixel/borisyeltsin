const banned = new Set([
  "password",
  "passphrase",
  "secret",
  "private_key",
  "privatekey",
  "cvv",
  "cvc",
  "pan",
  "recovery_key",
  "recoverykey",
  "vault_key",
  "vaultkey",
  "token",
  "code_verifier",
]);

export type SecretHit = {
  service: string;
  label: string;
  login: string;
  password: string;
};

function present(value: unknown): boolean {
  if (value == null) return false;
  if (typeof value === "string") return value.trim() !== "";
  return true;
}

export function splitBackup(raw: unknown): { document: unknown; secrets: SecretHit[] } {
  if (!raw || typeof raw !== "object") {
    throw new Error("Нужен файл резервной копии этого приложения.");
  }
  const doc = structuredClone(raw) as { version?: unknown; services?: unknown };
  if (doc.version !== 1 || !Array.isArray(doc.services) || doc.services.length > 500) {
    throw new Error("Нужен файл резервной копии этого приложения.");
  }
  const secrets: SecretHit[] = [];
  for (const service of doc.services) {
    if (!service || typeof service !== "object" || !("name" in service) || typeof service.name !== "string" || !service.name.trim()) {
      throw new Error("В файле есть некорректный сервис.");
    }
    if (!("accounts" in service) || !Array.isArray(service.accounts) || service.accounts.length > 200) {
      throw new Error("В файле есть некорректный сервис.");
    }
    for (const account of service.accounts) {
      if (!account || typeof account !== "object") {
        throw new Error("Некорректный аккаунт.");
      }
      const row = account as Record<string, unknown>;
      const password = typeof row.password === "string" ? row.password : "";
      delete row.password;
      for (const key of Object.keys(row)) {
        if (!banned.has(key.toLowerCase())) continue;
        if (present(row[key])) {
          throw new Error("Файл содержит секрет, который нельзя импортировать.");
        }
        delete row[key];
      }
      if (password.trim()) {
        secrets.push({
          service: service.name,
          label: typeof row.label === "string" ? row.label : "",
          login: typeof row.login === "string" ? row.login : "",
          password,
        });
      }
    }
  }
  return { document: doc, secrets };
}

export function secretKey(hit: Pick<SecretHit, "service" | "label" | "login">): string {
  return `${hit.service}\n${hit.label}\n${hit.login}`;
}
