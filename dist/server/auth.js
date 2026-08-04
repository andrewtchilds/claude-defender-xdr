import { InteractionRequiredAuthError, PublicClientApplication } from "@azure/msal-node";
import open from "open";
import { buildAuthority, buildScopes, GRAPH_CLOUDS } from "./config.js";
import { createPersistentCache } from "./cache.js";
export class AuthenticationRequiredError extends Error {
    constructor() { super("Interactive authentication is required. Run claude-defender-xdr-login; MCP tools never open a browser automatically."); this.name = "AuthenticationRequiredError"; }
}
function claims(token) { const p = token.split(".")[1]; if (!p)
    throw new Error("Microsoft returned an unexpected access token"); try {
    return JSON.parse(Buffer.from(p, "base64url").toString());
}
catch {
    throw new Error("Microsoft returned an unreadable access token");
} }
export function verifyDefenderToken(token, config) { const c = claims(token), expected = config.apiBaseUrl.replace(/\/+$/, "").toLowerCase(), aud = typeof c.aud === "string" ? c.aud.replace(/\/+$/, "").toLowerCase() : "", accepted = new Set([expected]); if (GRAPH_CLOUDS.has(expected))
    accepted.add("00000003-0000-0000-c000-000000000000"); if (!accepted.has(aud))
    throw new Error(`Token audience is not the configured hunting API (${config.apiBaseUrl})`); if (!(typeof c.scp === "string" && c.scp.split(/\s+/).some(s => s.toLowerCase() === "threathunting.read.all")))
    throw new Error("Token is missing the delegated ThreatHunting.Read.All scope"); if (typeof c.tid !== "string" || c.tid.toLowerCase() !== config.tenantId.toLowerCase())
    throw new Error("Token tenant does not match the configured tenant"); }
export class XdrAuth {
    config;
    cache;
    pca;
    constructor(config, cache, pca) {
        this.config = config;
        this.cache = cache;
        this.pca = pca;
    }
    static async create(config) { const cache = await createPersistentCache(config.allowUnencryptedTokenCache); const pca = new PublicClientApplication({ auth: { clientId: config.clientId, authority: buildAuthority(config) }, cache: { cachePlugin: cache.cachePlugin }, system: { loggerOptions: { piiLoggingEnabled: false, loggerCallback: () => undefined } } }); return new XdrAuth(config, cache, pca); }
    async accounts() { return this.pca.getAllAccounts(); }
    async account() { const a = await this.accounts(); if (a.length > 1)
        throw new Error("Multiple Defender XDR accounts are cached; use claude-defender-xdr-logout or remove the cache"); return a[0]; }
    async acquireTokenSilent() { const a = await this.account(); if (!a)
        throw new AuthenticationRequiredError(); try {
        const r = await this.pca.acquireTokenSilent({ account: a, scopes: buildScopes(this.config) });
        verifyDefenderToken(r.accessToken, this.config);
        return r;
    }
    catch (e) {
        if (e instanceof InteractionRequiredAuthError || (e && typeof e === "object" && "errorCode" in e && ["interaction_required", "consent_required", "login_required"].includes(String(e.errorCode))))
            throw new AuthenticationRequiredError();
        throw new Error(`Defender XDR authentication failed: ${sanitize(String(e instanceof Error ? e.message : e))}`);
    } }
    async login() { const r = await this.pca.acquireTokenInteractive({ scopes: buildScopes(this.config), openBrowser: async (url) => { await open(url, { wait: false }); }, successTemplate: "Authentication complete. Return to Claude Code.", errorTemplate: "Authentication failed. Return to Claude Code for details." }); verifyDefenderToken(r.accessToken, this.config); return r; }
    async logout(account) { await this.pca.signOut({ account }); }
}
function sanitize(s) { return s.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]").replace(/(?:access|refresh|id)[_-]?token\s*[:=]\s*\S+/gi, "token=[REDACTED]"); }
//# sourceMappingURL=auth.js.map