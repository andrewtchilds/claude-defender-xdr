import { InteractionRequiredAuthError, PublicClientApplication, } from "@azure/msal-node";
import open from "open";
import { buildAuthority, buildScopes, GRAPH_CLOUDS } from "./config.js";
import { createPersistentCache } from "./cache.js";
/** Graph's own resource app ID, which Entra issues as the audience for Graph scopes. */
const GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000";
const INTERACTIVE_ERROR_CODES = ["interaction_required", "consent_required", "login_required"];
export class AuthenticationRequiredError extends Error {
    constructor() {
        super("Interactive authentication is required. Run claude-defender-xdr-login; MCP tools never open a browser automatically.");
        this.name = "AuthenticationRequiredError";
    }
}
/**
 * Reads the unverified JWT payload. The signature is not checked here — Graph is the
 * authority on that. This exists to fail fast with an actionable message when MSAL hands
 * back a token for the wrong tenant, resource, or scope.
 */
function readClaims(token) {
    const payload = token.split(".")[1];
    if (!payload)
        throw new Error("Microsoft returned an unexpected access token");
    try {
        return JSON.parse(Buffer.from(payload, "base64url").toString());
    }
    catch {
        throw new Error("Microsoft returned an unreadable access token");
    }
}
export function verifyDefenderToken(token, config) {
    const claims = readClaims(token);
    const expectedAudience = config.apiBaseUrl.replace(/\/+$/, "").toLowerCase();
    const audience = typeof claims.aud === "string" ? claims.aud.replace(/\/+$/, "").toLowerCase() : "";
    const acceptedAudiences = new Set([expectedAudience]);
    if (GRAPH_CLOUDS.has(expectedAudience))
        acceptedAudiences.add(GRAPH_RESOURCE_APP_ID);
    if (!acceptedAudiences.has(audience)) {
        throw new Error(`Token audience is not the configured hunting API (${config.apiBaseUrl})`);
    }
    const scopes = typeof claims.scp === "string" ? claims.scp.split(/\s+/) : [];
    if (!scopes.some(scope => scope.toLowerCase() === "threathunting.read.all")) {
        throw new Error("Token is missing the delegated ThreatHunting.Read.All scope");
    }
    if (typeof claims.tid !== "string" || claims.tid.toLowerCase() !== config.tenantId.toLowerCase()) {
        throw new Error("Token tenant does not match the configured tenant");
    }
}
function needsInteraction(error) {
    if (error instanceof InteractionRequiredAuthError)
        return true;
    if (!error || typeof error !== "object" || !("errorCode" in error))
        return false;
    return INTERACTIVE_ERROR_CODES.includes(String(error.errorCode));
}
function sanitize(message) {
    return message
        .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
        .replace(/(?:access|refresh|id)[_-]?token\s*[:=]\s*\S+/gi, "token=[REDACTED]");
}
export class XdrAuth {
    config;
    cache;
    pca;
    constructor(config, cache, pca) {
        this.config = config;
        this.cache = cache;
        this.pca = pca;
    }
    static async create(config) {
        const cache = await createPersistentCache(config.allowUnencryptedTokenCache);
        const pca = new PublicClientApplication({
            auth: { clientId: config.clientId, authority: buildAuthority(config) },
            cache: { cachePlugin: cache.cachePlugin },
            // MSAL logging is silenced: its callbacks can carry tokens and account identifiers.
            system: { loggerOptions: { piiLoggingEnabled: false, loggerCallback: () => undefined } },
        });
        return new XdrAuth(config, cache, pca);
    }
    accounts() {
        return this.pca.getAllAccounts();
    }
    async singleAccount() {
        const accounts = await this.accounts();
        if (accounts.length > 1) {
            throw new Error("Multiple Defender XDR accounts are cached; use claude-defender-xdr-logout or remove the cache");
        }
        return accounts[0];
    }
    /** Never triggers a browser. Callers surface AuthenticationRequiredError to the user. */
    async acquireTokenSilent() {
        const account = await this.singleAccount();
        if (!account)
            throw new AuthenticationRequiredError();
        try {
            const result = await this.pca.acquireTokenSilent({
                account,
                scopes: buildScopes(this.config),
            });
            verifyDefenderToken(result.accessToken, this.config);
            return result;
        }
        catch (error) {
            if (needsInteraction(error))
                throw new AuthenticationRequiredError();
            const detail = error instanceof Error ? error.message : String(error);
            throw new Error(`Defender XDR authentication failed: ${sanitize(detail)}`);
        }
    }
    /** Only reached from the explicit login command, never from an MCP tool. */
    async login() {
        const result = await this.pca.acquireTokenInteractive({
            scopes: buildScopes(this.config),
            openBrowser: async (url) => {
                await open(url, { wait: false });
            },
            successTemplate: "Authentication complete. Return to Claude Code.",
            errorTemplate: "Authentication failed. Return to Claude Code for details.",
        });
        verifyDefenderToken(result.accessToken, this.config);
        return result;
    }
    /** Clears the local cache entry only; the Entra session elsewhere is untouched. */
    async logout(account) {
        await this.pca.signOut({ account });
    }
}
//# sourceMappingURL=auth.js.map