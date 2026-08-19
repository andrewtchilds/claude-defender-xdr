import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  configPath,
  loadConfig,
  NotConfiguredError,
  readStoredConfig,
  saveStoredConfig,
  stateDir,
} from "../src/config.js";

const TENANT = "31e14793-1820-4e78-bb77-295ff38db016";
const CLIENT = "c121ae43-424f-4d07-ba0d-c5e36b6538bb";
const OTHER_TENANT = "8f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607";
const valid = { XDR_TENANT_ID: TENANT, XDR_CLIENT_ID: CLIENT } as NodeJS.ProcessEnv;

// The stored config is passed explicitly so these cases never read the developer's own
// config file, which would otherwise satisfy the very cases meant to be unconfigured.
const none = {};

describe("loadConfig", () => {
  it("reads the tenant and client from the environment", () => {
    const config = loadConfig(valid, none);
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
  ])("falls back to the saved sign-in identity when the environment is %s", (_label, env) => {
    const config = loadConfig(env as NodeJS.ProcessEnv, { tenantId: TENANT, clientId: CLIENT });
    expect(config.tenantId).toBe(TENANT);
    expect(config.clientId).toBe(CLIENT);
  });

  // The regression that made this necessary: an install that never opened the
  // configuration dialog exported blanks, and blanks outranked a good saved config.
  it("never lets a blank environment override a saved identity", () => {
    const env = { XDR_TENANT_ID: "", XDR_CLIENT_ID: "${user_config.client_id}" } as NodeJS.ProcessEnv;
    expect(loadConfig(env, { tenantId: TENANT, clientId: CLIENT }).tenantId).toBe(TENANT);
  });

  it("lets a configured environment win over a saved identity", () => {
    const config = loadConfig({ ...valid, XDR_TENANT_ID: OTHER_TENANT }, { tenantId: TENANT, clientId: CLIENT });
    expect(config.tenantId).toBe(OTHER_TENANT);
  });

  it.each([
    ["missing", {}],
    ["empty", { XDR_TENANT_ID: "", XDR_CLIENT_ID: "" }],
    ["not a GUID", { XDR_TENANT_ID: "my-tenant", XDR_CLIENT_ID: CLIENT }],
  ])("points an unconfigured %s tenant at sign-in", (_label, env) => {
    expect(() => loadConfig(env as NodeJS.ProcessEnv, none)).toThrow(NotConfiguredError);
    expect(() => loadConfig(env as NodeJS.ProcessEnv, none)).toThrow(/xdr_login/);
  });

  it("pairs each sovereign cloud with its own login host", () => {
    expect(loadConfig({ ...valid, XDR_GRAPH_BASE_URL: "https://graph.microsoft.us" }, none).loginBaseUrl).toBe(
      "https://login.microsoftonline.us",
    );
  });

  it("refuses a Graph endpoint that is not Microsoft's", () => {
    expect(() => loadConfig({ ...valid, XDR_GRAPH_BASE_URL: "https://evil.example.com" }, none)).toThrow(
      NotConfiguredError,
    );
  });

  it("clamps max_rows into range and falls back on nonsense", () => {
    expect(loadConfig({ ...valid, XDR_MAX_ROWS: "50000" }, none).maxRows).toBe(10000);
    expect(loadConfig({ ...valid, XDR_MAX_ROWS: "0" }, none).maxRows).toBe(1);
    expect(loadConfig({ ...valid, XDR_MAX_ROWS: "" }, none).maxRows).toBe(1000);
    expect(loadConfig({ ...valid, XDR_MAX_ROWS: "lots" }, none).maxRows).toBe(1000);
  });

  it("falls back to 7d when the timespan is not a duration", () => {
    expect(loadConfig({ ...valid, XDR_DEFAULT_TIMESPAN: "24h" }, none).defaultTimespan).toBe("24h");
    expect(loadConfig({ ...valid, XDR_DEFAULT_TIMESPAN: "last tuesday" }, none).defaultTimespan).toBe("7d");
  });

  // Paths are compared through join() so the cases hold on Windows separators too.
  it("keeps state under the user's config directory", () => {
    expect(stateDir({ HOME: "/home/a" } as NodeJS.ProcessEnv, "linux")).toBe(
      join("/home/a", ".config", "claude-defender-xdr"),
    );
    expect(stateDir({ XDG_CONFIG_HOME: "/xdg" } as NodeJS.ProcessEnv, "darwin")).toBe(
      join("/xdg", "claude-defender-xdr"),
    );
    expect(configPath({ XDG_CONFIG_HOME: "/xdg" } as NodeJS.ProcessEnv)).toBe(
      join("/xdg", "claude-defender-xdr", "config.json"),
    );
  });

  it("keeps state under %APPDATA% on Windows, not a dotfile in the profile root", () => {
    const roaming = "C:\\Users\\a\\AppData\\Roaming";
    expect(stateDir({ APPDATA: roaming } as NodeJS.ProcessEnv, "win32")).toBe(
      join(roaming, "claude-defender-xdr"),
    );
    // A stripped environment can be missing APPDATA, so the profile is the fallback.
    expect(stateDir({ USERPROFILE: "C:\\Users\\a" } as NodeJS.ProcessEnv, "win32")).toBe(
      join("C:\\Users\\a", "AppData", "Roaming", "claude-defender-xdr"),
    );
  });
});

describe("the saved sign-in identity", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "xdr-config-"));
    env = { XDG_CONFIG_HOME: home } as NodeJS.ProcessEnv;
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("round-trips through the config file", async () => {
    await saveStoredConfig({ tenantId: TENANT, clientId: CLIENT }, env);
    expect(readStoredConfig(env)).toEqual({ tenantId: TENANT, clientId: CLIENT });
  });

  it("is what an otherwise unconfigured server resolves", async () => {
    await saveStoredConfig({ tenantId: TENANT, clientId: CLIENT }, env);
    expect(loadConfig({ ...env, XDR_TENANT_ID: "" }, readStoredConfig(env)).tenantId).toBe(TENANT);
  });

  // Windows has no POSIX modes; there the profile directory's ACL is the boundary instead.
  it.skipIf(process.platform === "win32")("is written owner-only, since it names the tenant", async () => {
    const path = await saveStoredConfig({ tenantId: TENANT, clientId: CLIENT }, env);
    const { mode } = await import("node:fs").then(fs => fs.promises.stat(path));
    expect(mode & 0o777).toBe(0o600);
  });

  it("normalises a GUID typed in upper case", async () => {
    await saveStoredConfig({ tenantId: TENANT.toUpperCase(), clientId: CLIENT }, env);
    expect(readStoredConfig(env).tenantId).toBe(TENANT);
  });

  it("refuses to save something that is not a GUID", async () => {
    await expect(saveStoredConfig({ tenantId: "my-tenant", clientId: CLIENT }, env)).rejects.toThrow(
      NotConfiguredError,
    );
    expect(readStoredConfig(env)).toEqual({});
  });

  it("reads as empty when absent or damaged, so sign-in can still configure", async () => {
    expect(readStoredConfig(env)).toEqual({});
    await writeFile(configPath(env), "not json", "utf8").catch(async () => {
      await saveStoredConfig({ tenantId: TENANT, clientId: CLIENT }, env);
      await writeFile(configPath(env), "not json", "utf8");
    });
    expect(readStoredConfig(env)).toEqual({});
  });

  it("does not leave a temp file behind", async () => {
    await saveStoredConfig({ tenantId: TENANT, clientId: CLIENT }, env);
    const { readdir } = await import("node:fs/promises");
    const files = await readdir(join(home, "claude-defender-xdr"));
    expect(files).toEqual(["config.json"]);
    expect(JSON.parse(await readFile(configPath(env), "utf8"))).toEqual({ tenantId: TENANT, clientId: CLIENT });
  });
});
