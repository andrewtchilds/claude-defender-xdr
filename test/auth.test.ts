import { describe, expect, it } from "vitest";
import { verifyDefenderToken } from "../server/auth.js";

const CONFIG = {
  apiBaseUrl: "https://graph.microsoft.com",
  tenantId: "11111111-1111-4111-8111-111111111111",
};

/** Builds an unsigned JWT: verifyDefenderToken only inspects claims, never the signature. */
function token(claims: Record<string, unknown>): string {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none" })}.${encode(claims)}.signature`;
}

const valid = {
  aud: "https://graph.microsoft.com",
  scp: "ThreatHunting.Read.All User.Read",
  tid: CONFIG.tenantId,
};

describe("verifyDefenderToken", () => {
  it("accepts a delegated hunting token for the configured tenant", () => {
    expect(() => verifyDefenderToken(token(valid), CONFIG)).not.toThrow();
  });

  it("accepts Graph's resource app ID as the audience", () => {
    const graphAppId = "00000003-0000-0000-c000-000000000000";
    expect(() => verifyDefenderToken(token({ ...valid, aud: graphAppId }), CONFIG)).not.toThrow();
  });

  it("is case- and trailing-slash-insensitive on audience and tenant", () => {
    const relaxed = { ...valid, aud: "https://Graph.Microsoft.com/", tid: CONFIG.tenantId.toUpperCase() };
    expect(() => verifyDefenderToken(token(relaxed), CONFIG)).not.toThrow();
  });

  it("rejects a token minted for another resource", () => {
    expect(() => verifyDefenderToken(token({ ...valid, aud: "https://attacker.example" }), CONFIG)).toThrow(
      "audience",
    );
  });

  it("rejects a token from another tenant", () => {
    const otherTenant = "33333333-3333-4333-8333-333333333333";
    expect(() => verifyDefenderToken(token({ ...valid, tid: otherTenant }), CONFIG)).toThrow("tenant");
  });

  it("rejects a token without the hunting scope", () => {
    expect(() => verifyDefenderToken(token({ ...valid, scp: "User.Read" }), CONFIG)).toThrow(
      "ThreatHunting.Read.All",
    );
    expect(() => verifyDefenderToken(token({ aud: valid.aud, tid: valid.tid }), CONFIG)).toThrow(
      "ThreatHunting.Read.All",
    );
  });

  it("does not treat a scope prefix as a match", () => {
    expect(() =>
      verifyDefenderToken(token({ ...valid, scp: "ThreatHunting.Read.AllTheThings" }), CONFIG),
    ).toThrow("ThreatHunting.Read.All");
  });

  it("rejects tokens it cannot parse", () => {
    expect(() => verifyDefenderToken("not-a-jwt", CONFIG)).toThrow("unexpected access token");
    expect(() => verifyDefenderToken("header.%%%.sig", CONFIG)).toThrow("unreadable access token");
  });
});
