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

function guid(value: unknown, name: string): string {
  const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} must be a GUID`);
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

/** Precedence: built-in defaults < stored config file < CLAUDE_XDR_* environment overrides. */
export async function loadConfig(
  options: { path?: string; env?: NodeJS.ProcessEnv } = {},
): Promise<XdrConfig> {
  const stored = await readStoredConfig(options.path);
  const env = options.env ?? process.env;
  return validateConfig({
    ...DEFAULT_CONFIG,
    ...stored,
    ...(env.CLAUDE_XDR_TENANT_ID ? { tenantId: env.CLAUDE_XDR_TENANT_ID } : {}),
    ...(env.CLAUDE_XDR_CLIENT_ID ? { clientId: env.CLAUDE_XDR_CLIENT_ID } : {}),
    ...(env.CLAUDE_XDR_API_BASE_URL ? { apiBaseUrl: env.CLAUDE_XDR_API_BASE_URL } : {}),
    ...(env.CLAUDE_XDR_AUTHORITY_HOST ? { authorityHost: env.CLAUDE_XDR_AUTHORITY_HOST } : {}),
  });
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
