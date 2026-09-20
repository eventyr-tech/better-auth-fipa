import { describe, expect, it } from "vitest";
import { requireFirstPartyTransactions } from "./transaction.js";

describe("first-party transaction requirement", () => {
  it("rejects missing or disabled transaction capability rather than running sequential writes", () => {
    expect(() => requireFirstPartyTransactions({})).toThrow(
      "database transactions enabled",
    );
    expect(() =>
      requireFirstPartyTransactions({
        options: { adapterConfig: { adapterId: "test", transaction: false } },
      }),
    ).toThrow("database transactions enabled");
    expect(() =>
      requireFirstPartyTransactions({
        options: { adapterConfig: { adapterId: "test" } },
      }),
    ).toThrow("database transactions enabled");
  });
});
