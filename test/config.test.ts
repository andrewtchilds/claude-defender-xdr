import { describe, expect, it } from "vitest";
import {
  buildAuthority,
  buildScopes,
  DEFAULT_CONFIG,
  loadConfig,
  validateConfig,
} from "../server/config.js";

const IDS = {
  tenantId: "11111111-1111-4111-8111-111111111111",
  clientId: "22222222-2222-4222-8222-222222222222",
};

const base = (overrides: Record<string, unknown> = {}) => ({ ...DEFAULT_CONFIG, ...IDS, ...overrides });

describe("validateConfig", () => {
  it("accepts a well-formed default configuration", () => {
    const config = validateConfig(base());
    expect(config.tenantId).toBe(IDS.tenantId);
    expect(config.clientId).toBe(IDS.clientId);
    expect(config.scopeMode).toBe("delegated");
  });

  it("refuses confidential-client credentials", () => {
    expect(() => validateConfig(base({ clientSecret: "nope" }))).toThrow("Client secrets");
    expect(() => validateConfig(base({ client_secret: "nope" }))).toThrow("Client secrets");
  });

  it("pins the API endpoint to an official Graph cloud", () => {
    expect(() => validateConfig(base({ apiBaseUrl: "https://attacker.example" }))).toThrow(
      "official Microsoft Graph",
    );
    expect(() => validateConfig(base({ apiBaseUrl: "http://graph.microsoft.com" }))).toThrow(
      "plain HTTPS URL",
    );
    expect(() => validateConfig(base({ apiBaseUrl: "not a url" }))).toThrow("must be an HTTPS URL");
    expect(() =>
      validateConfig(base({ apiBaseUrl: "https://user:pw@graph.microsoft.com" })),
    ).toThrow("plain HTTPS URL");
  });

  it("requires the authority to match the chosen Graph cloud", () => {
    expect(() =>
      validateConfig(base({ apiBaseUrl: "https://graph.microsoft.us" })),
    ).toThrow("authorityHost must be https://login.microsoftonline.us");

    const usGov = validateConfig(
      base({ apiBaseUrl: "https://graph.microsoft.us", authorityHost: "https://login.microsoftonline.us" }),
    );
    expect(usGov.apiBaseUrl).toBe("https://graph.microsoft.us");
  });

  it("keeps the redirect URI on loopback", () => {
    expect(() => validateConfig(base({ redirectUri: "https://evil.example/cb" }))).toThrow(
      "redirectUri",
    );
  });

  it("rejects malformed identifiers and bounds", () => {
    expect(() => validateConfig(base({ tenantId: "not-a-guid" }))).toThrow("tenantId must be a GUID");
    expect(() => validateConfig(base({ maximumRows: 0 }))).toThrow("maximumRows");
    expect(() => validateConfig(base({ maximumRows: 10001 }))).toThrow("maximumRows");
    expect(() => validateConfig(base({ maximumRows: 1.5 }))).toThrow("maximumRows");
    expect(() => validateConfig(base({ defaultLookback: "forever" }))).toThrow("defaultLookback");
    expect(() => validateConfig(base({ scopeMode: "app" }))).toThrow("scopeMode");
    expect(() => validateConfig(base({ allowUnencryptedTokenCache: "yes" }))).toThrow("boolean");
    expect(() => validateConfig([])).toThrow("JSON object");
  });
});

describe("authority and scopes", () => {
  it("builds a tenant-scoped authority", () => {
    expect(buildAuthority({ authorityHost: "https://login.microsoftonline.com/", tenantId: "t" })).toBe(
      "https://login.microsoftonline.com/t",
    );
  });

  it("requests only the delegated hunting scope by default", () => {
    expect(buildScopes({ apiBaseUrl: "https://graph.microsoft.com", scopeMode: "delegated" })).toEqual([
      "https://graph.microsoft.com/ThreatHunting.Read.All",
    ]);
    expect(buildScopes({ apiBaseUrl: "https://graph.microsoft.com", scopeMode: "default" })).toEqual([
      "https://graph.microsoft.com/.default",
    ]);
  });
});

describe("loadConfig", () => {
  const missingPath = "/nonexistent/claude-defender-xdr/config.json";

  it("lets environment overrides supply identifiers when no file exists", async () => {
    const config = await loadConfig({
      path: missingPath,
      env: { CLAUDE_XDR_TENANT_ID: IDS.tenantId, CLAUDE_XDR_CLIENT_ID: IDS.clientId },
    });
    expect(config.tenantId).toBe(IDS.tenantId);
    expect(config.apiBaseUrl).toBe(DEFAULT_CONFIG.apiBaseUrl);
  });

  it("still validates values that arrive from the environment", async () => {
    await expect(
      loadConfig({
        path: missingPath,
        env: {
          CLAUDE_XDR_TENANT_ID: IDS.tenantId,
          CLAUDE_XDR_CLIENT_ID: IDS.clientId,
          CLAUDE_XDR_API_BASE_URL: "https://attacker.example",
        },
      }),
    ).rejects.toThrow("official Microsoft Graph");
  });
});
