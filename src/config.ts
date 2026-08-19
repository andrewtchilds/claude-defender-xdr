import { readFileSync } from "node:fs";
import { chmod, mkdir, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Graph endpoints this plugin will talk to, each mapped to the Entra login host that
 * issues tokens for it. Pairing them here makes a mismatched authority unrepresentable.
 */
export const GRAPH_CLOUDS = new Map([
  ["https://graph.microsoft.com", "https://login.microsoftonline.com"],
  ["https://graph.microsoft.us", "https://login.microsoftonline.us"],
  ["https://microsoftgraph.chinacloudapi.cn", "https://login.chinacloudapi.cn"],
]);

/** The one delegated permission this plugin uses. Advanced Hunting is read-only. */
export const GRAPH_SCOPE = "ThreatHunting.Read.All";

/**
 * Reserved OIDC scopes, which are never prefixed with the resource URL. `offline_access`
 * yields the refresh token that keeps the user signed in; `openid profile` yield the
 * id_token that names the signed-in account.
 */
export const RESERVED_SCOPES = ["offline_access", "openid", "profile"];

export interface Config {
  tenantId: string;
  clientId: string;
  graphBaseUrl: string;
  loginBaseUrl: string;
  maxRows: number;
  defaultTimespan: string;
}

/** The tenant and app identity, as saved by sign-in. Neither value is a secret. */
export interface StoredConfig {
  tenantId?: string;
  clientId?: string;
}

/** Owner-only directory holding the refresh token and any exported result files. */
export function stateDir(env: NodeJS.ProcessEnv = process.env): string {
  const base = env.XDG_CONFIG_HOME || join(env.HOME || homedir(), ".config");
  return join(base, "claude-defender-xdr");
}

export function configPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(stateDir(env), "config.json");
}

export class NotConfiguredError extends Error {
  constructor(missing: string) {
    super(
      `Defender XDR is not configured: ${missing}.\n\n` +
        "Ask the user for their Entra tenant ID and application (client) ID — both are " +
        "GUIDs, and neither is a secret — then call xdr_login with tenant_id and " +
        "client_id. They are saved for next time and take effect immediately, with no " +
        "restart. The IDs can also be set up front with /plugin configure defender-xdr.",
    );
    this.name = "NotConfiguredError";
  }
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Narrows a raw setting to a value that was actually supplied.
 *
 * Claude Code substitutes an unset `user_config` entry as an empty string rather than
 * omitting the variable, and leaves the `${user_config.x}` placeholder verbatim when the
 * plugin was installed without ever opening the configuration dialog. Neither is a value,
 * and treating them as one is what made an unconfigured install override a good config
 * file with nothing.
 */
function present(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed || /^\$\{.*\}$/.test(trimmed)) return undefined;
  return trimmed;
}

/** Validates a GUID-shaped setting, naming it in the error so the fix is obvious. */
export function guid(value: string | undefined, label: string): string {
  const supplied = present(value);
  if (!supplied) throw new NotConfiguredError(`${label} is not set`);
  if (!GUID.test(supplied)) throw new NotConfiguredError(`${label} is not a GUID (got "${supplied}")`);
  return supplied.toLowerCase();
}

function integer(value: string | undefined, fallback: number, min: number, max: number): number {
  const trimmed = present(value);
  // Number("") is 0, so a blank variable must be rejected before parsing or an unset
  // numeric option would clamp to the minimum instead of using the default.
  if (!trimmed) return fallback;
  const parsed = Number(trimmed);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

/**
 * Reads the identity saved by a previous sign-in. Missing or damaged files read as empty
 * so a first run, or a hand-edited file, still reaches the "sign in to configure" path
 * instead of failing with a parse error.
 */
export function readStoredConfig(env: NodeJS.ProcessEnv = process.env): StoredConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(configPath(env), "utf8"));
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const { tenantId, clientId } = parsed as Record<string, unknown>;
  return {
    tenantId: present(typeof tenantId === "string" ? tenantId : undefined),
    clientId: present(typeof clientId === "string" ? clientId : undefined),
  };
}

/** Writes through a temp file so an interrupted save cannot leave a half-written config. */
export async function saveStoredConfig(
  values: Required<StoredConfig>,
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  const stored: Required<StoredConfig> = {
    tenantId: guid(values.tenantId, "tenant ID"),
    clientId: guid(values.clientId, "application (client) ID"),
  };
  const directory = stateDir(env);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700).catch(() => undefined);

  const path = configPath(env);
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(stored, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await chmod(temp, 0o600).catch(() => undefined);
  await rename(temp, path);
  return path;
}

/**
 * Resolves configuration from the environment Claude Code populates from `userConfig`,
 * falling back to the identity saved by sign-in.
 *
 * The fallback is what lets a fresh install work: `/plugin configure` is an interactive
 * dialog that some Claude Code surfaces cannot show, and values entered there reach this
 * process only when it next launches. Sign-in can supply the same two IDs at any time and
 * have them apply immediately.
 */
export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  stored: StoredConfig = readStoredConfig(env),
): Config {
  const graphBaseUrl = (present(env.XDR_GRAPH_BASE_URL) ?? "https://graph.microsoft.com").replace(/\/+$/, "");
  const loginBaseUrl = GRAPH_CLOUDS.get(graphBaseUrl);
  if (!loginBaseUrl) {
    throw new NotConfiguredError(
      `"${graphBaseUrl}" is not a Microsoft Graph endpoint (expected one of ${[...GRAPH_CLOUDS.keys()].join(", ")})`,
    );
  }

  const timespan = present(env.XDR_DEFAULT_TIMESPAN) ?? "7d";
  return {
    tenantId: guid(present(env.XDR_TENANT_ID) ?? stored.tenantId, "tenant ID"),
    clientId: guid(present(env.XDR_CLIENT_ID) ?? stored.clientId, "application (client) ID"),
    graphBaseUrl,
    loginBaseUrl,
    maxRows: integer(env.XDR_MAX_ROWS, 1000, 1, 10000),
    defaultTimespan: /^\d+[dh]$/i.test(timespan) ? timespan : "7d",
  };
}
