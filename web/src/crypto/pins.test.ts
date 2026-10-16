import { beforeEach, describe, expect, it } from "vitest";
import { groupFingerprint, pinKey, pinState, requireVerified } from "./pins";

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

  it("groups a SHA-256 fingerprint into 16 groups of 4", () => {
    const groups = groupFingerprint("0123456789abcdef".repeat(4));
    expect(groups).toHaveLength(16);
    expect(groups[15]).toBe("cdef");
  });
});
