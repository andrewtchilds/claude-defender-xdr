import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
export const GRAPH_CLOUDS = new Map([
    ["https://graph.microsoft.com", "https://login.microsoftonline.com"],
    ["https://graph.microsoft.us", "https://login.microsoftonline.us"],
    ["https://microsoftgraph.chinacloudapi.cn", "https://login.chinacloudapi.cn"],
]);
export const DEFAULT_CONFIG = {
    authorityHost: "https://login.microsoftonline.com", apiBaseUrl: "https://graph.microsoft.com",
    redirectUri: "http://localhost", defaultLookback: "7d", maximumRows: 1000, schemaTtlHours: 168,
    scopeMode: "delegated", allowUnencryptedTokenCache: false,
};
export function getXdrDirectory() { return join(process.env.XDG_CONFIG_HOME || join(process.env.HOME || ".", ".config"), "claude-defender-xdr"); }
export function getConfigPath() { return join(getXdrDirectory(), "config.json"); }
export function buildAuthority(c) { return `${c.authorityHost.replace(/\/+$/, "")}/${c.tenantId}`; }
export function buildScopes(c) { const r = c.apiBaseUrl.replace(/\/+$/, ""); return [c.scopeMode === "default" ? `${r}/.default` : `${r}/ThreatHunting.Read.All`]; }
function guid(v, name) { if (typeof v !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v))
    throw new Error(`${name} must be a GUID`); return v; }
function https(v, name) { if (typeof v !== "string")
    throw new Error(`${name} must be an HTTPS URL`); const u = new URL(v); if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash)
    throw new Error(`${name} must be a plain HTTPS URL`); return u.toString().replace(/\/$/, ""); }
export function validateConfig(input) {
    if (!input || typeof input !== "object" || Array.isArray(input))
        throw new Error("Configuration must be a JSON object");
    const v = input;
    if ("clientSecret" in v || "client_secret" in v)
        throw new Error("Client secrets are not supported");
    if (v.redirectUri !== "http://localhost")
        throw new Error('redirectUri must be "http://localhost"');
    if (typeof v.defaultLookback !== "string" || !/^\d+[dh]$/.test(v.defaultLookback))
        throw new Error("defaultLookback must be a duration such as 7d or 24h");
    if (!Number.isInteger(v.maximumRows) || Number(v.maximumRows) < 1 || Number(v.maximumRows) > 10000)
        throw new Error("maximumRows must be an integer from 1 to 10000");
    if (!Number.isInteger(v.schemaTtlHours) || Number(v.schemaTtlHours) < 1)
        throw new Error("schemaTtlHours must be positive");
    if (v.scopeMode !== "delegated" && v.scopeMode !== "default")
        throw new Error('scopeMode must be "delegated" or "default"');
    if (typeof v.allowUnencryptedTokenCache !== "boolean")
        throw new Error("allowUnencryptedTokenCache must be boolean");
    const apiBaseUrl = https(v.apiBaseUrl, "apiBaseUrl"), authorityHost = https(v.authorityHost, "authorityHost");
    const expected = GRAPH_CLOUDS.get(apiBaseUrl);
    if (!expected)
        throw new Error("apiBaseUrl must be an official Microsoft Graph cloud endpoint");
    if (authorityHost !== expected)
        throw new Error(`authorityHost must be ${expected} for ${apiBaseUrl}`);
    return { tenantId: guid(v.tenantId, "tenantId"), clientId: guid(v.clientId, "clientId"), authorityHost, apiBaseUrl, redirectUri: v.redirectUri, defaultLookback: v.defaultLookback, maximumRows: v.maximumRows, schemaTtlHours: v.schemaTtlHours, scopeMode: v.scopeMode, allowUnencryptedTokenCache: v.allowUnencryptedTokenCache };
}
export async function readStoredConfig(path = getConfigPath()) { try {
    const v = JSON.parse(await readFile(path, "utf8"));
    if (!v || typeof v !== "object" || Array.isArray(v))
        throw new Error("must contain a JSON object");
    return v;
}
catch (e) {
    if (e.code === "ENOENT")
        return {};
    throw new Error(`Unable to read Defender XDR config at ${path}: ${e.message}`);
} }
export async function loadConfig(options = {}) { const stored = await readStoredConfig(options.path); const env = options.env ?? process.env; return validateConfig({ ...DEFAULT_CONFIG, ...stored, ...(env.CLAUDE_XDR_TENANT_ID ? { tenantId: env.CLAUDE_XDR_TENANT_ID } : {}), ...(env.CLAUDE_XDR_CLIENT_ID ? { clientId: env.CLAUDE_XDR_CLIENT_ID } : {}), ...(env.CLAUDE_XDR_API_BASE_URL ? { apiBaseUrl: env.CLAUDE_XDR_API_BASE_URL } : {}), ...(env.CLAUDE_XDR_AUTHORITY_HOST ? { authorityHost: env.CLAUDE_XDR_AUTHORITY_HOST } : {}) }); }
export async function saveStoredConfig(config, path = getConfigPath()) { await mkdir(dirname(path), { recursive: true, mode: 0o700 }); await chmod(dirname(path), 0o700); const tmp = `${path}.${process.pid}.${Date.now()}.tmp`; try {
    await writeFile(tmp, `${JSON.stringify(config, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await chmod(tmp, 0o600);
    await rename(tmp, path);
}
finally {
    await rm(tmp, { force: true }).catch(() => undefined);
} }
//# sourceMappingURL=config.js.map