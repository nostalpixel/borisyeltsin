export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

let csrf = "";

export function setCsrf(token: string) {
  csrf = token;
}

export function clearCsrf() {
  csrf = "";
}

const messages: Record<string, string> = {
  access_denied: "Доступ закрыт.",
  invitation_invalid: "Приглашение недействительно.",
  approval_required: "Ожидается подтверждение ключа.",
  mfa_required: "Нужен второй фактор.",
  oidc_not_configured: "Вход через Authentik не настроен.",
  auth_required: "Нужно войти.",
  csrf: "Обновите страницу и повторите.",
  weak_kdf: "Параметры ключа слабее допустимых.",
  vault_locked: "Сейф закрыт. Откройте его парольной фразой.",
  recovery_not_ready: "Сначала назначьте двух хранителей восстановления.",
  recovery_envelope_missing: "Нет конверта восстановления для этой версии ключа.",
  secret_field: "В файле остались секреты. Пароль нужно зашифровать в браузере.",
  card_number: "Похоже на полный номер карты. Оставьте название и последние 4 цифры.",
  forbidden: "Недостаточно прав.",
  not_found: "Объект не найден.",
  rate_limited: "Слишком много попыток. Подождите минуту.",
  fingerprint_mismatch: "Отпечаток ключа не совпал.",
  envelope_mismatch: "Конверт относится к другому сейфу.",
  key_not_approved: "Ключ ещё не подтверждён.",
};

export function explain(error: unknown): string {
  if (error instanceof ApiError) {
    return messages[error.code] ?? "Запрос отклонён.";
  }
  if (error instanceof Error && error.message) {
    return messages[error.message] ?? error.message;
  }
  return "Запрос отклонён.";
}

export async function api<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-Requested-With": "fetch" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && method !== "HEAD" && csrf) {
    headers["X-CSRF-Token"] = csrf;
  }
  const response = await fetch(path, {
    method,
    headers,
    credentials: "include",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let data: { error?: string } = {};
  if (text) {
    try {
      data = JSON.parse(text) as { error?: string };
    } catch {
      data = {};
    }
  }
  if (!response.ok) {
    throw new ApiError(response.status, data.error ?? "server");
  }
  return data as T;
}
