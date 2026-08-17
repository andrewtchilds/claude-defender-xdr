import { describe, expect, it } from "vitest";
import {
  buildAuthority,
  buildScopes,
  DEFAULT_CONFIG,
  loadConfig,
  readClaudePluginOptions,
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
    expect(() => validateConfig(base({ tenantId: "not-a-guid" }))).toThrow("/plugin configure");
    expect(() => validateConfig(base({ tenantId: undefined }))).toThrow("tenantId is not set");
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
      claudeOptions: {},
      env: { CLAUDE_XDR_TENANT_ID: IDS.tenantId, CLAUDE_XDR_CLIENT_ID: IDS.clientId },
    });
    expect(config.tenantId).toBe(IDS.tenantId);
    expect(config.apiBaseUrl).toBe(DEFAULT_CONFIG.apiBaseUrl);
  });

  it("still validates values that arrive from the environment", async () => {
    await expect(
      loadConfig({
        path: missingPath,
        claudeOptions: {},
        env: {
          CLAUDE_XDR_TENANT_ID: IDS.tenantId,
          CLAUDE_XDR_CLIENT_ID: IDS.clientId,
          CLAUDE_XDR_API_BASE_URL: "https://attacker.example",
        },
      }),
    ).rejects.toThrow("official Microsoft Graph");
  });
});

describe("Claude Code plugin options", () => {
  const missingPath = "/nonexistent/claude-defender-xdr/config.json";

  it("configures the plugin entirely from CLAUDE_PLUGIN_OPTION_* variables", async () => {
    const config = await loadConfig({
      path: missingPath,
      claudeOptions: {},
      env: {
        CLAUDE_PLUGIN_OPTION_TENANT_ID: IDS.tenantId,
        CLAUDE_PLUGIN_OPTION_CLIENT_ID: IDS.clientId,
        CLAUDE_PLUGIN_OPTION_MAXIMUM_ROWS: "250",
        CLAUDE_PLUGIN_OPTION_DEFAULT_LOOKBACK: "24h",
        CLAUDE_PLUGIN_OPTION_ALLOW_UNENCRYPTED_TOKEN_CACHE: "false",
      },
    });
    expect(config.tenantId).toBe(IDS.tenantId);
    expect(config.maximumRows).toBe(250);
    expect(config.defaultLookback).toBe("24h");
    expect(config.allowUnencryptedTokenCache).toBe(false);
  });

  it("derives the authority host when a sovereign cloud is selected", async () => {
    const config = await loadConfig({
      path: missingPath,
      claudeOptions: {},
      env: {
        CLAUDE_PLUGIN_OPTION_TENANT_ID: IDS.tenantId,
        CLAUDE_PLUGIN_OPTION_CLIENT_ID: IDS.clientId,
        CLAUDE_PLUGIN_OPTION_API_BASE_URL: "https://graph.microsoft.us",
      },
    });
    expect(config.authorityHost).toBe("https://login.microsoftonline.us");
  });

  it("accepts the documented boolean spellings", async () => {
    for (const [raw, expected] of [["true", true], ["1", true], ["Yes", true], ["false", false]] as const) {
      const config = await loadConfig({
        path: missingPath,
        claudeOptions: {},
        env: {
          CLAUDE_PLUGIN_OPTION_TENANT_ID: IDS.tenantId,
          CLAUDE_PLUGIN_OPTION_CLIENT_ID: IDS.clientId,
          CLAUDE_PLUGIN_OPTION_ALLOW_UNENCRYPTED_TOKEN_CACHE: raw,
        },
      });
      expect(config.allowUnencryptedTokenCache, raw).toBe(expected);
    }
  });

  it("lets an explicit CLAUDE_XDR_* override win over the plugin option", async () => {
    const other = "44444444-4444-4444-8444-444444444444";
    const config = await loadConfig({
      path: missingPath,
      claudeOptions: {},
      env: {
        CLAUDE_PLUGIN_OPTION_TENANT_ID: IDS.tenantId,
        CLAUDE_PLUGIN_OPTION_CLIENT_ID: IDS.clientId,
        CLAUDE_XDR_TENANT_ID: other,
      },
    });
    expect(config.tenantId).toBe(other);
  });
});

describe("reading userConfig from Claude Code settings", () => {
  const missingPath = "/nonexistent/claude-defender-xdr/config.json";

  it("applies options the user entered at the plugin prompt", async () => {
    const config = await loadConfig({
      path: missingPath,
      env: {},
      claudeOptions: {
        tenant_id: IDS.tenantId,
        client_id: IDS.clientId,
        maximum_rows: 500,
        allow_unencrypted_token_cache: true,
      },
    });
    expect(config.tenantId).toBe(IDS.tenantId);
    expect(config.maximumRows).toBe(500);
    expect(config.allowUnencryptedTokenCache).toBe(true);
  });

  it("ignores blank and wrongly typed option values", async () => {
    const config = await loadConfig({
      path: missingPath,
      env: {},
      claudeOptions: {
        tenant_id: IDS.tenantId,
        client_id: IDS.clientId,
        default_lookback: "",
        maximum_rows: "500",
        allow_unencrypted_token_cache: "true",
      },
    });
    expect(config.defaultLookback).toBe(DEFAULT_CONFIG.defaultLookback);
    expect(config.maximumRows).toBe(DEFAULT_CONFIG.maximumRows);
    expect(config.allowUnencryptedTokenCache).toBe(false);
  });

  it("returns nothing when settings are absent or unreadable", async () => {
    expect(await readClaudePluginOptions({ CLAUDE_CONFIG_DIR: "/nonexistent/claude" })).toEqual({});
  });

  it("lets the MCP server environment win over stored settings", async () => {
    const other = "44444444-4444-4444-8444-444444444444";
    const config = await loadConfig({
      path: missingPath,
      env: { CLAUDE_PLUGIN_OPTION_TENANT_ID: other },
      claudeOptions: { tenant_id: IDS.tenantId, client_id: IDS.clientId },
    });
    expect(config.tenantId).toBe(other);
  });
});
