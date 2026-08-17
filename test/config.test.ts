import { describe, expect, it } from "vitest";
import { loadConfig, NotConfiguredError, stateDir } from "../src/config.js";

const TENANT = "31e14793-1820-4e78-bb77-295ff38db016";
const CLIENT = "c121ae43-424f-4d07-ba0d-c5e36b6538bb";
const valid = { XDR_TENANT_ID: TENANT, XDR_CLIENT_ID: CLIENT } as NodeJS.ProcessEnv;

describe("loadConfig", () => {
  it("reads the tenant and client from the environment", () => {
    const config = loadConfig(valid);
    expect(config.tenantId).toBe(TENANT);
    expect(config.clientId).toBe(CLIENT);
    expect(config.graphBaseUrl).toBe("https://graph.microsoft.com");
    expect(config.loginBaseUrl).toBe("https://login.microsoftonline.com");
  });

  // Claude Code substitutes an unconfigured user_config value as an empty string rather
  // than omitting the variable, so blank must be treated exactly like missing.
  it.each([
    ["missing", {}],
    ["empty", { XDR_TENANT_ID: "", XDR_CLIENT_ID: "" }],
    ["whitespace", { XDR_TENANT_ID: "   ", XDR_CLIENT_ID: "   " }],
    ["unsubstituted placeholder", { XDR_TENANT_ID: "${user_config.tenant_id}", XDR_CLIENT_ID: CLIENT }],
    ["not a GUID", { XDR_TENANT_ID: "my-tenant", XDR_CLIENT_ID: CLIENT }],
  ])("rejects a %s tenant with actionable guidance", (_label, env) => {
    expect(() => loadConfig(env as NodeJS.ProcessEnv)).toThrow(NotConfiguredError);
    expect(() => loadConfig(env as NodeJS.ProcessEnv)).toThrow(/\/plugin configure defender-xdr/);
  });

  it("pairs each sovereign cloud with its own login host", () => {
    expect(loadConfig({ ...valid, XDR_GRAPH_BASE_URL: "https://graph.microsoft.us" }).loginBaseUrl).toBe(
      "https://login.microsoftonline.us",
    );
  });

  it("refuses a Graph endpoint that is not Microsoft's", () => {
    expect(() => loadConfig({ ...valid, XDR_GRAPH_BASE_URL: "https://evil.example.com" })).toThrow(
      NotConfiguredError,
    );
  });

  it("clamps max_rows into range and falls back on nonsense", () => {
    expect(loadConfig({ ...valid, XDR_MAX_ROWS: "50000" }).maxRows).toBe(10000);
    expect(loadConfig({ ...valid, XDR_MAX_ROWS: "0" }).maxRows).toBe(1);
    expect(loadConfig({ ...valid, XDR_MAX_ROWS: "" }).maxRows).toBe(1000);
    expect(loadConfig({ ...valid, XDR_MAX_ROWS: "lots" }).maxRows).toBe(1000);
  });

  it("falls back to 7d when the timespan is not a duration", () => {
    expect(loadConfig({ ...valid, XDR_DEFAULT_TIMESPAN: "24h" }).defaultTimespan).toBe("24h");
    expect(loadConfig({ ...valid, XDR_DEFAULT_TIMESPAN: "last tuesday" }).defaultTimespan).toBe("7d");
  });

  it("keeps state under the user's config directory", () => {
    expect(stateDir({ HOME: "/home/a" } as NodeJS.ProcessEnv)).toBe("/home/a/.config/claude-defender-xdr");
    expect(stateDir({ XDG_CONFIG_HOME: "/xdg" } as NodeJS.ProcessEnv)).toBe("/xdg/claude-defender-xdr");
  });
});
