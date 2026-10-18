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

// groupFingerprint splits a value into 4-character groups for reading aloud.
export function groupFingerprint(value: string, size = 4): string[] {
  const groups: string[] = [];
  for (let i = 0; i < value.length; i += size) groups.push(value.slice(i, i + size));
  return groups;
}
