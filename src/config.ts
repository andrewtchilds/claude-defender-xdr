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

/** Owner-only directory holding the refresh token and any exported result files. */
export function stateDir(env: NodeJS.ProcessEnv = process.env): string {
  const base = env.XDG_CONFIG_HOME || join(env.HOME || homedir(), ".config");
  return join(base, "claude-defender-xdr");
}

export class NotConfiguredError extends Error {
  constructor(missing: string) {
    super(
      `Defender XDR is not configured: ${missing}.\n\n` +
        "Run /plugin configure defender-xdr and supply your Entra tenant ID and " +
        "application (client) ID, then restart Claude Code so the server picks them up.",
    );
    this.name = "NotConfiguredError";
  }
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function guid(value: string | undefined, label: string): string {
  const trimmed = value?.trim() ?? "";
  // Claude Code substitutes an unset user_config value as an empty string rather than
  // omitting the variable, so "missing" and "blank" are the same case here.
  if (!trimmed) throw new NotConfiguredError(`${label} is not set`);
  if (!GUID.test(trimmed)) throw new NotConfiguredError(`${label} is not a GUID (got "${trimmed}")`);
  return trimmed.toLowerCase();
}

function integer(value: string | undefined, fallback: number, min: number, max: number): number {
  const trimmed = value?.trim();
  // Number("") is 0, so a blank variable must be rejected before parsing or an unset
  // numeric option would clamp to the minimum instead of using the default.
  if (!trimmed) return fallback;
  const parsed = Number(trimmed);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

/**
 * The single source of configuration: environment variables that Claude Code populates
 * from `userConfig` when it launches this server. There is deliberately no config file
 * and no settings.json parsing, so what the user typed in the plugin dialog is what runs.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const graphBaseUrl = (env.XDR_GRAPH_BASE_URL?.trim() || "https://graph.microsoft.com").replace(/\/+$/, "");
  const loginBaseUrl = GRAPH_CLOUDS.get(graphBaseUrl);
  if (!loginBaseUrl) {
    throw new NotConfiguredError(
      `"${graphBaseUrl}" is not a Microsoft Graph endpoint (expected one of ${[...GRAPH_CLOUDS.keys()].join(", ")})`,
    );
  }

  const timespan = env.XDR_DEFAULT_TIMESPAN?.trim() || "7d";
  return {
    tenantId: guid(env.XDR_TENANT_ID, "tenant ID"),
    clientId: guid(env.XDR_CLIENT_ID, "application (client) ID"),
    graphBaseUrl,
    loginBaseUrl,
    maxRows: integer(env.XDR_MAX_ROWS, 1000, 1, 10000),
    defaultTimespan: /^\d+[dh]$/i.test(timespan) ? timespan : "7d",
  };
}
