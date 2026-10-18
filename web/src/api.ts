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
  recovery_not_ready: "Recovery isn't set up, so new passwords are blocked. Open Vault › Recovery.",
  recovery_envelope_missing: "The vault key isn't sealed to the recovery key yet. An owner does that in Vault › Recovery.",
  recovery_unavailable: "Recovery is not available: it isn't set up, a custodian left, or it was already used.",
  recovery_epoch_changed: "The recovery key changed in the meantime. Reload and try again.",
  recovery_rollback: "The server offered an older recovery key than this browser has seen. Do not continue; tell an admin.",
  recovery_needs_verification: "Verify the recovery key first. Ask a custodian to read its fingerprint to you.",
  recovery_key_changed: "The recovery key fingerprint differs from the one this browser verified. Do not continue; tell an admin.",
  recovery_envelope_not_allowed: "A recovery rotation cannot reseal the used recovery key.",
  custodians_not_distinct: "Choose two different people with different keys.",
  not_custodian: "Only a recovery custodian can do this.",
  too_many_challenges: "Too many recovery attempts this hour. Wait and try again.",
  challenge_invalid: "That recovery attempt expired or was already used. Start again.",
  challenge_failed: "The recovery proof failed. Check both shares and start again.",
  challenge_mismatch: "The server's challenge did not match this recovery. Do not continue; tell an admin.",
  grant_expired: "The 15-minute recovery window ended. Start again.",
  shares_do_not_match: "The two shares do not make the recovery key. Check the other custodian's share.",
  bad_share: "That share is not valid. It should be 44 characters ending in '='.",
  share_mismatch: "Your share does not match this recovery key, or it did not come from the admin who set it up.",
  nothing_to_confirm: "There is no share waiting for you to confirm.",
  epoch_not_pending: "This recovery key is no longer waiting for confirmation.",
  key_changed: "Your key changed after the share was sent to you. Ask an admin to set up recovery again.",
  envelope_set: "The new key must go to every member, and to you during a recovery.",
  secret_field: "The file still contains secrets. Passwords must be encrypted in the browser.",
  card_number: "This looks like a full card number. Keep only a name and the last 4 digits.",
  forbidden: "You do not have permission.",
  not_found: "Not found.",
  rate_limited: "Too many attempts. Wait a minute.",
  fingerprint_mismatch: "The key fingerprint does not match.",
  envelope_mismatch: "This envelope belongs to a different vault.",
  key_not_approved: "The key is not approved yet.",
  bad_recovery_key: "The recovery key did not work.",
  no_access: "This vault is not shared with you yet. Ask a vault owner to share it.",
  not_key_holder: "Only an owner who holds the current vault key can do this. Unlock the vault first.",
  last_vault_owner: "This person is the vault's only owner. Make another member an owner first.",
  stale_key: "The vault key changed since you unlocked it. Lock and unlock the vault, then try again.",
  item_conflict: "Someone else changed this password. Reload the vault, then make your change again.",
  items_changed: "Passwords changed during the rotation. Reload the vault and rotate again.",
  version_conflict: "The vault key was already rotated. Reload the vault.",
  vault_busy: "The vault is busy. Try again in a moment.",
  bad_passphrase: "That passphrase did not unlock your key. Check it, or use your recovery key.",
  item_conflict_reloaded: "Someone else changed this password just now. Their version is loaded; your text is still in the field. Save again to replace theirs.",
  needs_verification: "Verify this person's key first. Compare the fingerprint with them, then try again.",
  vault_exists: "This organization already has a vault. Ask an owner to share it with you.",
  proposal_rejected: "Replacement key rejected.",
  owner_envelope_first: "The vault owner has to unlock the vault once before sharing it.",
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
