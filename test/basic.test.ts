import { describe, expect, it } from "vitest";
import { normalizeTimespan } from "../server/client.js";
import { DEFAULT_CONFIG, validateConfig } from "../server/config.js";

const ids = {
  tenantId: "11111111-1111-4111-8111-111111111111",
  clientId: "22222222-2222-4222-8222-222222222222",
};

describe("Claude Defender XDR adapter", () => {
  it("normalizes supported Graph timespans", () => {
    expect(normalizeTimespan("7d")).toBe("P7D");
    expect(normalizeTimespan("24h")).toBe("PT24H");
    expect(normalizeTimespan("p7d")).toBe("P7D");
    expect(() => normalizeTimespan("forever")).toThrow();
  });

  it("rejects client secrets and non-Graph endpoints", () => {
    const valid = validateConfig({ ...DEFAULT_CONFIG, ...ids });
    expect(valid.clientId).toBe(ids.clientId);
    expect(() => validateConfig({ ...DEFAULT_CONFIG, ...ids, clientSecret: "nope" })).toThrow("Client secrets");
    expect(() => validateConfig({ ...DEFAULT_CONFIG, ...ids, apiBaseUrl: "https://attacker.example" })).toThrow("official Microsoft Graph");
  });
});
