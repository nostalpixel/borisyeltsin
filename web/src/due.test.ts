import { describe, expect, it } from "vitest";
import { daysUntil, dueLabel, dueLevel } from "./due";

describe("due paint", () => {
  it("matches the reference windows", () => {
    expect(daysUntil("2026-11-01", "2026-10-25")).toBe(7);
    expect(dueLevel(7)).toBe("warning");
    expect(dueLevel(4)).toBe("warning");
    expect(dueLevel(3)).toBe("danger");
    expect(dueLevel(0)).toBe("danger");
    expect(dueLevel(-2)).toBe("danger");
    expect(dueLevel(8)).toBe("");
    expect(dueLabel(-2)).toBe("Просрочено на 2 дн.");
    expect(dueLabel(0)).toBe("Оплата сегодня");
    expect(dueLabel(5)).toBe("Оплата через 5 дн.");
    expect(daysUntil("2026-02-31", "2026-02-01")).toBeNull();
  });
});
