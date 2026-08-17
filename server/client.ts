import type { XdrAuth } from "./auth.js";
import type { XdrConfig } from "./config.js";

/** Hard ceiling on a single Graph response body, to bound memory before parsing. */
export const MAX_RESPONSE_BYTES = 25 * 1024 * 1024;

/** Wall-clock budget for one hunting request, including retries. */
export const REQUEST_TIMEOUT_MS = 4 * 60 * 1000;

const MAX_ATTEMPTS = 3;
const MAX_RETRY_DELAY_MS = 30_000;
const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);

export interface HuntingColumn {
  name: string;
  type?: string;
  [key: string]: unknown;
}

export interface HuntingQueryResult {
  schema: HuntingColumn[];
  results: Record<string, unknown>[];
}

export class XdrApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "XdrApiError";
  }
}

const CANCELLED = "Defender XDR query cancelled";

/** Accepts the shorthand forms the skills use (`7d`, `24h`) plus raw ISO-8601 durations. */
export function normalizeTimespan(value: string): string {
  const trimmed = value.trim();
  const shorthand = /^(\d+)([dh])$/i.exec(trimmed);
  if (shorthand) {
    return shorthand[2]!.toLowerCase() === "d" ? `P${shorthand[1]}D` : `PT${shorthand[1]}H`;
  }
  if (/^P(?=\d|T\d)(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$/i.test(trimmed)) {
    return trimmed.toUpperCase();
  }
  throw new Error("timespan must be a duration such as 7d, 24h, P7D, or PT24H");
}

function sanitize(message: string): string {
  return message
    .slice(0, 4000)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]");
}

/** Handles both the delta-seconds and HTTP-date forms of Retry-After. */
function parseRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined;
  const trimmed = header.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? undefined : Math.max(0, Math.ceil((parsed - Date.now()) / 1000));
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new Error(CANCELLED));
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(new Error(CANCELLED));
      },
      { once: true },
    );
  });
}

function describeFailure(status: number, retryAfterSeconds: number | undefined): string {
  switch (status) {
    case 400:
      return "Invalid hunting query";
    case 401:
      return "Microsoft Graph rejected the access token; run claude-defender-xdr-login";
    case 403:
      return "Access denied; verify delegated ThreatHunting.Read.All admin consent and Defender RBAC";
    case 429:
      return `Defender XDR query throttled${
        retryAfterSeconds === undefined ? "" : `; retry after ${retryAfterSeconds}s`
      }`;
    default:
      return "Defender XDR query failed";
  }
}

function assertHuntingShape(value: Record<string, unknown>): HuntingQueryResult {
  if (!Array.isArray(value.schema) || !Array.isArray(value.results)) {
    throw new Error("Microsoft Graph hunting response is missing schema or results");
  }
  const badSchema = value.schema.some(
    column =>
      !column ||
      typeof column !== "object" ||
      typeof (column as Record<string, unknown>).name !== "string",
  );
  const badRows = value.results.some(row => !row || typeof row !== "object" || Array.isArray(row));
  if (badSchema || badRows) {
    throw new Error("Microsoft Graph hunting response contains invalid schema or result rows");
  }
  return {
    schema: value.schema as HuntingColumn[],
    results: value.results as Record<string, unknown>[],
  };
}

/**
 * POSTs one Advanced Hunting query to Graph. Retries only idempotent-safe transient
 * failures (429 and 5xx) and only when the server's Retry-After stays within budget.
 */
export async function runHuntingQuery(
  auth: XdrAuth,
  config: XdrConfig,
  input: { query: string; timespan?: string },
  signal?: AbortSignal,
): Promise<HuntingQueryResult> {
  if (!input.query.trim()) throw new Error("Hunting query must not be empty");

  const token = await auth.acquireTokenSilent();
  const body = JSON.stringify({
    Query: input.query,
    ...(input.timespan ? { Timespan: normalizeTimespan(input.timespan) } : {}),
  });

  const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  const deadline: AbortSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
  const cancelled = () => new Error(signal?.aborted ? CANCELLED : "Defender XDR query timed out");

  for (let attempt = 0; ; attempt++) {
    let response: Response;
    try {
      response = await fetch(`${config.apiBaseUrl}/v1.0/security/runHuntingQuery`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token.accessToken}`,
          "content-type": "application/json; charset=utf-8",
        },
        body,
        signal: deadline,
      });
    } catch (error) {
      if (deadline.aborted || (error instanceof Error && error.name === "AbortError")) throw cancelled();
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`Defender XDR request failed: ${sanitize(detail)}`);
    }

    const retryAfterSeconds = parseRetryAfter(response.headers.get("retry-after"));
    const retryable = RETRYABLE_STATUSES.has(response.status) && attempt < MAX_ATTEMPTS - 1;
    if (retryable) {
      // Exponential backoff unless the server named a (short enough) delay of its own.
      const waitMs =
        retryAfterSeconds === undefined ? 1000 * 2 ** attempt : retryAfterSeconds * 1000;
      if (waitMs <= MAX_RETRY_DELAY_MS) {
        await response.body?.cancel();
        await delay(waitMs, deadline);
        continue;
      }
    }

    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
      throw new Error(
        "Microsoft Graph hunting response exceeded the 25 MiB safety limit; narrow the query or timespan",
      );
    }

    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      throw new Error(
        response.ok
          ? "Microsoft Graph returned malformed JSON"
          : `Defender XDR query failed (${response.status})`,
      );
    }

    const value = parsed as Record<string, unknown>;
    if (!response.ok) {
      const graphError = value.error as Record<string, unknown> | undefined;
      const detail = sanitize(String(graphError?.message ?? value.message ?? `HTTP ${response.status}`));
      throw new XdrApiError(
        `${describeFailure(response.status, retryAfterSeconds)} (${response.status}): ${detail}`,
        response.status,
        retryAfterSeconds,
      );
    }

    return assertHuntingShape(value);
  }
}
