import { beforeEach, describe, expect, it } from "vitest";
import { groupFingerprint, pinKey, pinRecoveryKey, pinState, recoveryPinState, requireRecoveryVerified, requireVerified } from "./pins";

class MemoryStorage {
  private data = new Map<string, string>();
  getItem(key: string) {
    return this.data.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.data.set(key, value);
  }
}

describe("fingerprint pins", () => {
  beforeEach(() => {
    (globalThis as { window?: unknown }).window = { localStorage: new MemoryStorage() };
  });

  it("is unverified until someone confirms the fingerprint", () => {
    expect(pinState("me", "anna", "aaaa").state).toBe("unverified");
    expect(() => requireVerified("me", "anna", "aaaa")).toThrow("needs_verification");
  });

  it("accepts the pinned key and blocks a different one", () => {
    pinKey("me", "anna", "aaaa", new Date("2026-10-17T10:00:00Z"));
    expect(pinState("me", "anna", "aaaa")).toEqual({ state: "verified", at: "2026-10-17" });
    expect(pinState("me", "anna", "bbbb")).toEqual({ state: "changed", at: "2026-10-17" });
    expect(() => requireVerified("me", "anna", "bbbb")).toThrow("needs_verification");
  });

  it("keeps pins per viewer", () => {
    pinKey("me", "anna", "aaaa");
    expect(pinState("someone-else", "anna", "aaaa").state).toBe("unverified");
  });

  it("treats blocked storage as nothing pinned", () => {
    (globalThis as { window?: unknown }).window = {
      localStorage: {
        getItem() {
          throw new Error("blocked");
        },
        setItem() {
          throw new Error("blocked");
        },
      },
    };
    pinKey("me", "anna", "aaaa");
    expect(pinState("me", "anna", "aaaa").state).toBe("unverified");
  });

  it("pins the recovery key with its epoch and refuses a rollback", () => {
    expect(() => requireRecoveryVerified("me", "org", "aaaa", 2)).toThrow("recovery_needs_verification");
    pinRecoveryKey("me", "org", "aaaa", 2);
    expect(recoveryPinState("me", "org", "aaaa", 2).state).toBe("verified");
    expect(recoveryPinState("me", "org", "bbbb", 2).state).toBe("changed");
    // A newer epoch is a new key to verify; an older one is a rollback.
    expect(recoveryPinState("me", "org", "cccc", 3).state).toBe("unverified");
    expect(recoveryPinState("me", "org", "zzzz", 1).state).toBe("rollback");
    expect(() => requireRecoveryVerified("me", "org", "zzzz", 1)).toThrow("recovery_rollback");
    expect(() => pinRecoveryKey("me", "org", "zzzz", 1)).toThrow("recovery_rollback");
    // Recovery pins do not collide with people's pins.
    expect(pinState("me", "org", "aaaa").state).toBe("unverified");
  });

  it("groups a SHA-256 fingerprint into 16 groups of 4", () => {
    const groups = groupFingerprint("0123456789abcdef".repeat(4));
    expect(groups).toHaveLength(16);
    expect(groups[15]).toBe("cdef");
  });
});
