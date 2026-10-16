import { describe, expect, it } from "vitest";
// The CSS file itself, not a copy of its values, is what gets checked.
import css from "./theme.css?raw";

function token(name: string): string {
  const match = css.match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`));
  if (!match) throw new Error(`missing token --${name}`);
  return match[1];
}

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

describe("theme tokens", () => {
  it("keeps every text color readable on every surface", () => {
    for (const text of ["text", "muted", "alert", "warn", "ok"]) {
      for (const surface of ["bg", "panel", "panel-2"]) {
        expect(contrast(token(text), token(surface)), `${text} on ${surface}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it("keeps button text readable on primary and its hover", () => {
    expect(contrast(token("text"), token("primary"))).toBeGreaterThanOrEqual(4.5);
    expect(contrast(token("text"), token("primary-hover"))).toBeGreaterThanOrEqual(4.5);
  });

  it("keeps borders and the focus ring visible", () => {
    expect(contrast(token("line"), token("bg"))).toBeGreaterThanOrEqual(3);
    expect(contrast(token("line"), token("panel"))).toBeGreaterThanOrEqual(3);
    expect(contrast(token("focus"), token("bg"))).toBeGreaterThanOrEqual(3);
  });

  it("keeps primary and alert visibly different reds", () => {
    expect(token("primary")).not.toBe(token("alert"));
    expect(contrast(token("alert"), token("primary"))).toBeGreaterThanOrEqual(1.5);
  });
});
