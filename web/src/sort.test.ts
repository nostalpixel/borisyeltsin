import { describe, expect, it } from "vitest";
import type { Service } from "./types";
import { sortServices } from "./workspace";

const svc = (id: string, name: string, created_at: string) => ({ id, name, created_at }) as Service;

describe("sortServices", () => {
  const rows = [svc("1", "linode", "2026-01-03T00:00:00Z"), svc("2", "Server 10", "2026-01-01T00:00:00Z"), svc("3", "Árvore", "2026-01-02T00:00:00Z"), svc("4", "Server 2", "2026-01-04T00:00:00Z")];
  const names = (order: Parameters<typeof sortServices>[1]) => sortServices(rows, order).map((row) => row.name);

  it("sorts by name ignoring case and accents, numbers by value", () => {
    expect(names("az")).toEqual(["Árvore", "linode", "Server 2", "Server 10"]);
    expect(names("za")).toEqual(["Server 10", "Server 2", "linode", "Árvore"]);
  });

  it("sorts by date added", () => {
    expect(names("newest")).toEqual(["Server 2", "linode", "Árvore", "Server 10"]);
    expect(names("oldest")).toEqual(["Server 10", "Árvore", "linode", "Server 2"]);
  });

  it("leaves the input alone", () => {
    sortServices(rows, "za");
    expect(rows[0].name).toBe("linode");
  });
});
