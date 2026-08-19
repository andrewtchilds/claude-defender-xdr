import type { Authenticator } from "./auth.js";
import type { Config } from "./config.js";

/** Bounds memory before parsing a response body. */
const MAX_RESPONSE_BYTES = 25 * 1024 * 1024;

/** Wall-clock budget for one hunting request, including retries. */
const REQUEST_TIMEOUT_MS = 4 * 60 * 1000;

const MAX_ATTEMPTS = 3;
const MAX_RETRY_DELAY_MS = 30_000;
const RETRYABLE = new Set([429, 500, 502, 503, 504]);

export interface HuntingResult {
  schema: { name: string; type?: string }[];
  results: Record<string, unknown>[];
}

/** Accepts the shorthand the skills use (`7d`, `24h`) as well as raw ISO-8601 durations. */
export function normalizeTimespan(value: string): string {
  const trimmed = value.trim();
  const shorthand = /^(\d+)\s*([dh])$/i.exec(trimmed);
  if (shorthand) {
    return shorthand[2]!.toLowerCase() === "d" ? `P${shorthand[1]}D` : `PT${shorthand[1]}H`;
  }
  if (/^P(?=\d|T\d)(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$/i.test(trimmed)) {
    return trimmed.toUpperCase();
  }
  throw new Error(`timespan must be a duration such as 7d, 24h, P7D, or PT24H (got "${value}")`);
}

function sanitize(message: string): string {
  return message
    .slice(0, 2000)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]");
}

/** Retry-After arrives either as delta-seconds or as an HTTP date. */
function retryAfterMs(header: string | null): number | undefined {
  if (!header) return undefined;
  const trimmed = header.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1000;
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? undefined : Math.max(0, parsed - Date.now());
}

function explain(status: number): string {
  switch (status) {
    case 400:
      return "Defender XDR rejected the KQL query";
    case 401:
      return "Microsoft rejected the access token; sign in again with the xdr_login tool";
    case 403:
      return "Access denied: confirm admin consent for delegated ThreatHunting.Read.All and your Defender XDR role";
    case 429:
      return "Defender XDR throttled the query";
    default:
      return `Defender XDR query failed (HTTP ${status})`;
  }
}

function assertShape(value: Record<string, unknown>): HuntingResult {
  const { schema, results } = value;
  if (!Array.isArray(schema) || !Array.isArray(results)) {
    throw new Error("Microsoft Graph returned a hunting response without schema or results");
  }
  if (results.some(row => !row || typeof row !== "object" || Array.isArray(row))) {
    throw new Error("Microsoft Graph returned malformed hunting result rows");
  }
  return value as unknown as HuntingResult;
}

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => (clearTimeout(timer), reject(new Error("timed out"))), {
      once: true,
    });
  });

/**
 * POSTs one Advanced Hunting query to Graph. The API is read-only by construction: KQL
 * hunting queries cannot mutate tenant state, and the delegated scope is read-only too.
 */
export async function runHuntingQuery(
  auth: Authenticator,
  config: Config,
  input: { query: string; timespan?: string },
): Promise<HuntingResult> {
  if (!input.query.trim()) throw new Error("The KQL query must not be empty");

  const token = await auth.accessTokenSilent();
  const body = JSON.stringify({
    Query: input.query,
    ...(input.timespan ? { Timespan: normalizeTimespan(input.timespan) } : {}),
  });
  const deadline = AbortSignal.timeout(REQUEST_TIMEOUT_MS);

  for (let attempt = 0; ; attempt++) {
    let response: Response;
    try {
      response = await fetch(`${config.graphBaseUrl}/v1.0/security/runHuntingQuery`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json; charset=utf-8",
        },
        body,
        signal: deadline,
      });
    } catch (error) {
      if (deadline.aborted) throw new Error("Defender XDR query timed out after 4 minutes");
      throw new Error(`Could not reach Microsoft Graph: ${sanitize((error as Error).message)}`);
    }

    if (RETRYABLE.has(response.status) && attempt < MAX_ATTEMPTS - 1) {
      const waitMs = retryAfterMs(response.headers.get("retry-after")) ?? 1000 * 2 ** attempt;
      if (waitMs <= MAX_RETRY_DELAY_MS) {
        await response.body?.cancel();
        await sleep(waitMs, deadline);
        continue;
      }
    }

    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
      throw new Error("The hunting response exceeded 25 MiB; narrow the query or shorten the timespan");
    }

    let parsed: Record<string, unknown>;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      if (response.ok) throw new Error("Microsoft Graph returned malformed JSON");
      throw new Error(explain(response.status));
    }

    if (!response.ok) {
      const graphError = parsed.error as { message?: unknown } | undefined;
      const detail = sanitize(String(graphError?.message ?? parsed.message ?? ""));
      throw new Error(detail ? `${explain(response.status)}: ${detail}` : explain(response.status));
    }
    return assertShape(parsed);
  }
}
