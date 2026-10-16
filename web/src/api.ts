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
  access_denied: "Access denied.",
  invitation_invalid: "This invitation is not valid.",
  approval_required: "Waiting for key approval.",
  mfa_required: "A second factor is required.",
  oidc_not_configured: "Sign-in through Authentik is not configured.",
  auth_required: "Please sign in.",
  csrf: "Reload the page and try again.",
  weak_kdf: "Key parameters are weaker than allowed.",
  vault_locked: "The vault is locked. Unlock it with your passphrase.",
  recovery_not_ready: "Assign two recovery custodians first.",
  recovery_envelope_missing: "No recovery envelope exists for this key version.",
  secret_field: "The file still contains secrets. Passwords must be encrypted in the browser.",
  card_number: "This looks like a full card number. Keep only a name and the last 4 digits.",
  forbidden: "You do not have permission.",
  not_found: "Not found.",
  rate_limited: "Too many attempts. Wait a minute.",
  fingerprint_mismatch: "The key fingerprint does not match.",
  envelope_mismatch: "This envelope belongs to a different vault.",
  key_not_approved: "The key is not approved yet.",
  bad_recovery_key: "The recovery key did not work.",
};

export function explain(error: unknown): string {
  if (error instanceof ApiError) {
    return messages[error.code] ?? "Request rejected.";
  }
  if (error instanceof Error && error.message) {
    return messages[error.message] ?? error.message;
  }
  return "Request rejected.";
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
