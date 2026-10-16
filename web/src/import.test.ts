import { describe, expect, it } from "vitest";
import { secretKey, splitBackup } from "./import";

describe("splitBackup", () => {
  it("removes passwords and keeps the metadata document", () => {
    const { document, secrets } = splitBackup({
      version: 1,
      services: [
        {
          name: "Zomro",
          accounts: [{ label: "Аккаунт 1", login: "ops@example.com", password: "hunter2", cost: "12.5" }],
        },
      ],
    });
    const body = JSON.stringify(document);
    expect(body).not.toContain("hunter2");
    expect(body).not.toContain("password");
    expect(secrets).toEqual([{ service: "Zomro", label: "Аккаунт 1", login: "ops@example.com", password: "hunter2" }]);
    expect(secretKey(secrets[0])).toContain("Zomro");
  });

  it("allows an empty password and rejects other secret fields", () => {
    const { secrets } = splitBackup({
      version: 1,
      services: [{ name: "Chat", accounts: [{ label: "A", login: "", password: "" }] }],
    });
    expect(secrets).toEqual([]);
    expect(() =>
      splitBackup({
        version: 1,
        services: [{ name: "Chat", accounts: [{ label: "A", secret: "nope" }] }],
      }),
    ).toThrow(/секрет/);
  });
});
