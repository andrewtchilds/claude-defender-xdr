export const MAX_RESPONSE_BYTES = 25 * 1024 * 1024;
export class XdrApiError extends Error {
    status;
    retryAfterSeconds;
    constructor(message, status, retryAfterSeconds) {
        super(message);
        this.status = status;
        this.retryAfterSeconds = retryAfterSeconds;
        this.name = "XdrApiError";
    }
}
export function normalizeTimespan(v) { const x = v.trim(), s = /^(\d+)([dh])$/i.exec(x); if (s)
    return s[2].toLowerCase() === "d" ? `P${s[1]}D` : `PT${s[1]}H`; if (/^P(?=\d|T\d)(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$/i.test(x))
    return x.toUpperCase(); throw new Error("timespan must be a duration such as 7d, 24h, P7D, or PT24H"); }
export async function runHuntingQuery(auth, config, input, signal) { if (!input.query.trim())
    throw new Error("Hunting query must not be empty"); const token = await auth.acquireTokenSilent(); const body = JSON.stringify({ Query: input.query, ...(input.timespan ? { Timespan: normalizeTimespan(input.timespan) } : {}) }); for (let attempt = 0;; attempt++) {
    let response;
    try {
        response = await fetch(`${config.apiBaseUrl}/v1.0/security/runHuntingQuery`, { method: "POST", headers: { authorization: `Bearer ${token.accessToken}`, "content-type": "application/json; charset=utf-8" }, body, ...(signal ? { signal } : {}) });
    }
    catch (e) {
        if (signal?.aborted || (e instanceof Error && e.name === "AbortError"))
            throw new Error("Defender XDR query cancelled");
        throw new Error(`Defender XDR request failed: ${sanitize(e instanceof Error ? e.message : String(e))}`);
    }
    const retry = parseRetryAfter(response.headers.get("retry-after"));
    if (response.status === 429 && attempt < 2 && retry !== undefined && retry * 1000 <= 30000) {
        await response.body?.cancel();
        await delay(retry * 1000, signal);
        continue;
    }
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES)
        throw new Error("Microsoft Graph hunting response exceeded the 25 MiB safety limit; narrow the query or timespan");
    let parsed;
    try {
        parsed = text ? JSON.parse(text) : {};
    }
    catch {
        throw new Error(response.ok ? "Microsoft Graph returned malformed JSON" : `Defender XDR query failed (${response.status})`);
    }
    if (!response.ok) {
        const v = parsed, e = v.error, message = sanitize(String(e?.message ?? v.message ?? `HTTP ${response.status}`));
        const prefix = response.status === 400 ? "Invalid hunting query" : response.status === 401 ? "Microsoft Graph rejected the access token; run claude-defender-xdr-login" : response.status === 403 ? "Access denied; verify delegated ThreatHunting.Read.All admin consent and Defender RBAC" : response.status === 429 ? `Defender XDR query throttled${retry === undefined ? "" : `; retry after ${retry}s`}` : "Defender XDR query failed";
        throw new XdrApiError(`${prefix} (${response.status}): ${message}`, response.status, retry);
    }
    const v = parsed;
    if (!Array.isArray(v.schema) || !Array.isArray(v.results))
        throw new Error("Microsoft Graph hunting response is missing schema or results");
    if (v.schema.some(c => !c || typeof c !== "object" || typeof c.name !== "string") || v.results.some(r => !r || typeof r !== "object" || Array.isArray(r)))
        throw new Error("Microsoft Graph hunting response contains invalid schema or result rows");
    return { schema: v.schema, results: v.results };
} }
function sanitize(s) { return s.slice(0, 4000).replace(/[\r\n\t]+/g, " ").replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]"); }
function parseRetryAfter(v) { if (!v)
    return undefined; if (/^\d+$/.test(v.trim()))
    return Number(v.trim()); const d = Date.parse(v); return Number.isNaN(d) ? undefined : Math.max(0, Math.ceil((d - Date.now()) / 1000)); }
function delay(ms, signal) { return new Promise((resolve, reject) => { if (signal?.aborted)
    return reject(new Error("Defender XDR query cancelled")); const timer = setTimeout(resolve, ms); signal?.addEventListener("abort", () => { clearTimeout(timer); reject(new Error("Defender XDR query cancelled")); }, { once: true }); }); }
//# sourceMappingURL=client.js.map