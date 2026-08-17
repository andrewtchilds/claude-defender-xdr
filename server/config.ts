import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

/** Microsoft Graph endpoints this plugin will talk to, mapped to their required Entra authority. */
export const GRAPH_CLOUDS = new Map([
  ["https://graph.microsoft.com", "https://login.microsoftonline.com"],
  ["https://graph.microsoft.us", "https://login.microsoftonline.us"],
  ["https://microsoftgraph.chinacloudapi.cn", "https://login.chinacloudapi.cn"],
]);

export const DEFAULT_CONFIG = {
  authorityHost: "https://login.microsoftonline.com",
  apiBaseUrl: "https://graph.microsoft.com",
  redirectUri: "http://localhost",
  defaultLookback: "7d",
  maximumRows: 1000,
  schemaTtlHours: 168,
  scopeMode: "delegated" as const,
  allowUnencryptedTokenCache: false,
};

export type ScopeMode = "delegated" | "default";

export interface XdrConfig {
  tenantId: string;
  clientId: string;
  authorityHost: string;
  apiBaseUrl: string;
  redirectUri: string;
  defaultLookback: string;
  maximumRows: number;
  schemaTtlHours: number;
  scopeMode: ScopeMode;
  allowUnencryptedTokenCache: boolean;
}

export function getXdrDirectory(): string {
  const base = process.env.XDG_CONFIG_HOME || join(process.env.HOME || ".", ".config");
  return join(base, "claude-defender-xdr");
}

export function getConfigPath(): string {
  return join(getXdrDirectory(), "config.json");
}

export function buildAuthority(c: Pick<XdrConfig, "authorityHost" | "tenantId">): string {
  return `${c.authorityHost.replace(/\/+$/, "")}/${c.tenantId}`;
}

export function buildScopes(c: Pick<XdrConfig, "apiBaseUrl" | "scopeMode">): string[] {
  const resource = c.apiBaseUrl.replace(/\/+$/, "");
  return [c.scopeMode === "default" ? `${resource}/.default` : `${resource}/ThreatHunting.Read.All`];
}

const OPTION_KEYS: Record<string, string> = { tenantId: "tenant_id", clientId: "client_id" };

function guid(value: unknown, name: string): string {
  const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (typeof value !== "string" || !pattern.test(value)) {
    const option = OPTION_KEYS[name];
    // Point at the plugin dialog rather than a validation rule the user never wrote.
    const fix = option
      ? ` Set "${option}" by running /plugin configure defender-xdr.`
      : "";
    const detail = value === undefined || value === "" ? "is not set" : "must be a GUID";
    throw new Error(`${name} ${detail}.${fix}`);
  }
  return value;
}

/** Accepts only a bare HTTPS origin: no credentials, query, or fragment. */
function https(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`${name} must be an HTTPS URL`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an HTTPS URL, received ${JSON.stringify(value)}`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error(`${name} must be a plain HTTPS URL`);
  }
  return url.toString().replace(/\/$/, "");
}

export function validateConfig(input: unknown): XdrConfig {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Configuration must be a JSON object");
  }
  const v = input as Record<string, unknown>;

  if ("clientSecret" in v || "client_secret" in v) throw new Error("Client secrets are not supported");
  if (v.redirectUri !== "http://localhost") throw new Error('redirectUri must be "http://localhost"');
  if (typeof v.defaultLookback !== "string" || !/^\d+[dh]$/.test(v.defaultLookback)) {
    throw new Error("defaultLookback must be a duration such as 7d or 24h");
  }
  if (!Number.isInteger(v.maximumRows) || Number(v.maximumRows) < 1 || Number(v.maximumRows) > 10000) {
    throw new Error("maximumRows must be an integer from 1 to 10000");
  }
  if (!Number.isInteger(v.schemaTtlHours) || Number(v.schemaTtlHours) < 1) {
    throw new Error("schemaTtlHours must be positive");
  }
  if (v.scopeMode !== "delegated" && v.scopeMode !== "default") {
    throw new Error('scopeMode must be "delegated" or "default"');
  }
  if (typeof v.allowUnencryptedTokenCache !== "boolean") {
    throw new Error("allowUnencryptedTokenCache must be boolean");
  }

  const apiBaseUrl = https(v.apiBaseUrl, "apiBaseUrl");
  const authorityHost = https(v.authorityHost, "authorityHost");
  const expectedAuthority = GRAPH_CLOUDS.get(apiBaseUrl);
  if (!expectedAuthority) throw new Error("apiBaseUrl must be an official Microsoft Graph cloud endpoint");
  if (authorityHost !== expectedAuthority) {
    throw new Error(`authorityHost must be ${expectedAuthority} for ${apiBaseUrl}`);
  }

  return {
    tenantId: guid(v.tenantId, "tenantId"),
    clientId: guid(v.clientId, "clientId"),
    authorityHost,
    apiBaseUrl,
    redirectUri: v.redirectUri,
    defaultLookback: v.defaultLookback,
    maximumRows: v.maximumRows as number,
    schemaTtlHours: v.schemaTtlHours as number,
    scopeMode: v.scopeMode,
    allowUnencryptedTokenCache: v.allowUnencryptedTokenCache,
  };
}

/** Returns `{}` when no config file exists yet, so first-run login can prompt for one. */
export async function readStoredConfig(path = getConfigPath()): Promise<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("must contain a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw new Error(`Unable to read Defender XDR config at ${path}: ${(error as Error).message}`);
  }
}

function bool(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}

function integer(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value.trim());
  return Number.isFinite(parsed) ? parsed : undefined;
}

function defined<T extends object>(entries: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(entries).filter(([, value]) => value !== undefined),
  ) as Partial<T>;
}

const PLUGIN_NAME = "defender-xdr";

/** Maps `userConfig` option keys onto this module's config shape. */
function fromOptions(options: Record<string, unknown>) {
  const text = (value: unknown) => (typeof value === "string" && value ? value : undefined);
  return defined({
    tenantId: text(options.tenant_id),
    clientId: text(options.client_id),
    apiBaseUrl: text(options.api_base_url),
    defaultLookback: text(options.default_lookback),
    maximumRows: typeof options.maximum_rows === "number" ? options.maximum_rows : undefined,
    allowUnencryptedTokenCache:
      typeof options.allow_unencrypted_token_cache === "boolean"
        ? options.allow_unencrypted_token_cache
        : undefined,
  });
}

/**
 * Values collected by Claude Code's `userConfig` prompt, which it exports to plugin
 * subprocesses as CLAUDE_PLUGIN_OPTION_<KEY>. This is how the MCP server is configured.
 */
function pluginOptions(env: NodeJS.ProcessEnv) {
  return defined({
    tenantId: env.CLAUDE_PLUGIN_OPTION_TENANT_ID,
    clientId: env.CLAUDE_PLUGIN_OPTION_CLIENT_ID,
    apiBaseUrl: env.CLAUDE_PLUGIN_OPTION_API_BASE_URL,
    defaultLookback: env.CLAUDE_PLUGIN_OPTION_DEFAULT_LOOKBACK,
    maximumRows: integer(env.CLAUDE_PLUGIN_OPTION_MAXIMUM_ROWS),
    allowUnencryptedTokenCache: bool(env.CLAUDE_PLUGIN_OPTION_ALLOW_UNENCRYPTED_TOKEN_CACHE),
  });
}

function claudeSettingsPath(env: NodeJS.ProcessEnv): string {
  const base = env.CLAUDE_CONFIG_DIR || join(env.HOME || ".", ".claude");
  return join(base, "settings.json");
}

/**
 * Reads the same `userConfig` values from Claude Code's user settings.
 *
 * Claude Code exports CLAUDE_PLUGIN_OPTION_* only to MCP server and hook subprocesses,
 * not to the Bash tool, so the login helper cannot see them. Reading the documented
 * `pluginConfigs` location lets sign-in use the values the user already entered at the
 * plugin prompt instead of asking for them a second time.
 */
export async function readClaudePluginOptions(
  env: NodeJS.ProcessEnv = process.env,
): Promise<Record<string, unknown>> {
  let settings: Record<string, unknown>;
  try {
    settings = JSON.parse(await readFile(claudeSettingsPath(env), "utf8"));
  } catch {
    return {};
  }
  const configs = settings?.pluginConfigs;
  if (!configs || typeof configs !== "object") return {};

  // The key is `<plugin>@<marketplace>`, and the marketplace name varies by install.
  const entry = Object.entries(configs as Record<string, unknown>).find(
    ([key]) => key === PLUGIN_NAME || key.startsWith(`${PLUGIN_NAME}@`),
  )?.[1] as { options?: unknown } | undefined;

  const options = entry?.options;
  return options && typeof options === "object" ? (options as Record<string, unknown>) : {};
}

/**
 * Precedence, lowest to highest: built-in defaults, stored config file, Claude Code
 * plugin options (from user settings, then from the environment), and finally
 * CLAUDE_XDR_* variables as a deliberate manual override.
 *
 * The authority host is derived from the chosen Graph cloud unless explicitly set, so
 * selecting a sovereign cloud through the plugin prompt cannot leave the two mismatched.
 */
export async function loadConfig(
  options: { path?: string; env?: NodeJS.ProcessEnv; claudeOptions?: Record<string, unknown> } = {},
): Promise<XdrConfig> {
  const env = options.env ?? process.env;
  const stored = await readStoredConfig(options.path);
  const claudeOptions = options.claudeOptions ?? (await readClaudePluginOptions(env));

  const merged: Record<string, unknown> = {
    ...DEFAULT_CONFIG,
    ...stored,
    ...fromOptions(claudeOptions),
    ...pluginOptions(env),
    ...defined({
      tenantId: env.CLAUDE_XDR_TENANT_ID,
      clientId: env.CLAUDE_XDR_CLIENT_ID,
      apiBaseUrl: env.CLAUDE_XDR_API_BASE_URL,
      authorityHost: env.CLAUDE_XDR_AUTHORITY_HOST,
    }),
  };

  const explicitAuthority = env.CLAUDE_XDR_AUTHORITY_HOST ?? (stored.authorityHost as string | undefined);
  if (!explicitAuthority && typeof merged.apiBaseUrl === "string") {
    const derived = GRAPH_CLOUDS.get(merged.apiBaseUrl.replace(/\/+$/, ""));
    if (derived) merged.authorityHost = derived;
  }

  return validateConfig(merged);
}

/** Writes atomically through an owner-only temp file so a crash cannot leave a partial config. */
export async function saveStoredConfig(config: object, path = getConfigPath()): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(path), 0o700);
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(tmp, `${JSON.stringify(config, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    await chmod(tmp, 0o600);
    await rename(tmp, path);
  } finally {
    await rm(tmp, { force: true }).catch(() => undefined);
  }
}
