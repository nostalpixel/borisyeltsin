// Fingerprint pins: which colleague keys this browser has verified.
//
// The server hands out public keys, and a compromised server could hand out
// its own. So the browser seals a vault key only to a key whose fingerprint a
// person compared out of band (on a call, in person) and confirmed here. The
// confirmed fingerprint is pinned; later seals to the same key need no
// prompt, and a different key for the same person is blocked until someone
// verifies it again.
//
// Pins live in localStorage per viewer. If storage is unavailable, nothing is
// pinned and every seal asks for verification, which is safe, only slower.

export type PinState = { state: "verified"; at: string } | { state: "unverified" } | { state: "changed"; at: string };

type PinRecord = { fp: string; at: string };

function storageKey(viewerId: string): string {
  return `borisyeltsin.pins.v1:${viewerId}`;
}

function readPins(viewerId: string): Record<string, PinRecord> {
  try {
    const raw = window.localStorage.getItem(storageKey(viewerId));
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, PinRecord>) : {};
  } catch {
    return {};
  }
}

export function pinState(viewerId: string, userId: string, fingerprint: string): PinState {
  const pin = readPins(viewerId)[userId];
  if (!pin) return { state: "unverified" };
  if (pin.fp === fingerprint) return { state: "verified", at: pin.at };
  return { state: "changed", at: pin.at };
}

export function pinKey(viewerId: string, userId: string, fingerprint: string, now = new Date()) {
  const pins = readPins(viewerId);
  pins[userId] = { fp: fingerprint, at: now.toISOString().slice(0, 10) };
  try {
    window.localStorage.setItem(storageKey(viewerId), JSON.stringify(pins));
  } catch {
    // Storage blocked: the verification still counts for this action.
  }
}

// requireVerified throws unless the key is pinned with exactly this fingerprint.
export function requireVerified(viewerId: string, userId: string, fingerprint: string) {
  if (pinState(viewerId, userId, fingerprint).state !== "verified") {
    throw new Error("needs_verification");
  }
}

// The organization recovery key is pinned like a person's key, plus the
// epoch it belongs to (docs/CRYPTO.md "Rollback"). An older epoch than the
// pinned one is a rollback and is never accepted; a newer epoch is a new
// recovery key and needs verifying like any unknown key.

export type RecoveryPinState = PinState | { state: "rollback"; at: string; epoch: number };

type RecoveryPinRecord = PinRecord & { epoch?: number };

function recoveryId(orgId: string): string {
  return `recovery:${orgId}`;
}

export function recoveryPinState(viewerId: string, orgId: string, fingerprint: string, epoch: number): RecoveryPinState {
  const pin = readPins(viewerId)[recoveryId(orgId)] as RecoveryPinRecord | undefined;
  if (!pin) return { state: "unverified" };
  const pinned = pin.epoch ?? 0;
  if (epoch < pinned) return { state: "rollback", at: pin.at, epoch: pinned };
  if (epoch > pinned) return { state: "unverified" };
  return pin.fp === fingerprint ? { state: "verified", at: pin.at } : { state: "changed", at: pin.at };
}

export function pinRecoveryKey(viewerId: string, orgId: string, fingerprint: string, epoch: number, now = new Date()) {
  if (recoveryPinState(viewerId, orgId, fingerprint, epoch).state === "rollback") {
    throw new Error("recovery_rollback");
  }
  const pins = readPins(viewerId);
  pins[recoveryId(orgId)] = { fp: fingerprint, at: now.toISOString().slice(0, 10), epoch } as RecoveryPinRecord;
  try {
    window.localStorage.setItem(storageKey(viewerId), JSON.stringify(pins));
  } catch {
    // Storage blocked: the verification still counts for this action.
  }
}

export function requireRecoveryVerified(viewerId: string, orgId: string, fingerprint: string, epoch: number) {
  const pin = recoveryPinState(viewerId, orgId, fingerprint, epoch);
  if (pin.state === "rollback") throw new Error("recovery_rollback");
  if (pin.state !== "verified") throw new Error("recovery_needs_verification");
}

// groupFingerprint splits a value into 4-character groups for reading aloud.
export function groupFingerprint(value: string, size = 4): string[] {
  const groups: string[] = [];
  for (let i = 0; i < value.length; i += size) groups.push(value.slice(i, i + size));
  return groups;
}
