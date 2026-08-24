import { createHash, randomBytes, randomUUID } from "node:crypto";
import { join } from "node:path";
import {
  CLIENT_CAPABILITIES_META_KEY,
  createRequestStateCodec,
  inputRequired,
  inputResponse,
  McpServer,
  type ClientCapabilities,
  type InputRequiredResult,
  type ServerContext,
} from "@modelcontextprotocol/server";
import { z } from "zod";
// The manifest version is imported, not restated, so the version Claude sees over MCP cannot
// drift from the one the plugin was packaged and released under.
import manifest from "../.claude-plugin/plugin.json" with { type: "json" };
import {
  Authenticator,
  clearStoredToken,
  NotSignedInError,
  SIGN_IN_TIMEOUT_MS,
  type AuthenticatorOptions,
} from "./auth.js";
import {
  loadConfig,
  makeOwnerOnlyDir,
  NotConfiguredError,
  readStoredConfig,
  saveStoredConfig,
  stateDir,
  writeOwnerOnlyFile,
  type Config,
} from "./config.js";
import { GraphRequestError, runHuntingQuery } from "./graph.js";
import {
  clearLiveCache,
  liveColumns,
  mergeColumns,
  referencedTables,
  searchLiveCache,
  warmTables,
  type LiveColumns,
} from "./live-schema.js";
import { findTable, listTables, schema, searchTables, suggestTables, tableNames } from "./schema.js";

/** Keeps one tool result well inside the model's context budget. */
const MAX_OUTPUT_BYTES = 50 * 1024;

/**
 * How long a rejected query will wait for schema help before going out without it. The probes
 * are usually cache hits or one quick call, but a throttled tenant retries with waits, and the
 * rejection itself is the answer the model needs first.
 */
const REJECTED_HELP_TIMEOUT_MS = 10_000;

const SIGN_IN_RESPONSE_KEY = "defender-sign-in";

type SignInPurpose = "xdr-login" | "xdr-run-query";

type SignInRequestState = {
  version: 1;
  purpose: SignInPurpose;
  attemptId: string;
  flowId: string;
  tenantId: string;
  clientId: string;
  argumentFingerprint: string;
};

/** One process serves every stdio round, so an ephemeral process key is sufficient. */
const signInStateCodec = createRequestStateCodec<SignInRequestState>({
  key: randomBytes(32),
  ttlSeconds: SIGN_IN_TIMEOUT_MS / 1000,
});

/** Replay protection for accepted, declined, and cancelled rounds. */
const consumedSignInFlows = new Map<string, number>();

/**
 * Configuration and the authenticator are resolved on first use rather than at startup,
 * so the server still connects (and `xdr_get_schema` still answers) when the plugin has
 * not been configured yet. Only a successful resolution is cached, and `reset` drops it,
 * so configuring through `xdr_login` applies to the very next call without a restart.
 */
type Resettable<T> = (() => T) & { reset(): void };

function resettable<T>(create: () => T): Resettable<T> {
  let cached: T | undefined;
  const get = (() => (cached ??= create())) as Resettable<T>;
  get.reset = () => {
    cached = undefined;
  };
  return get;
}

export interface ServerRuntime {
  config: Resettable<Config>;
  auth: Resettable<Authenticator>;
}

/** Shares process-local configuration and pending OAuth attempts across MCP request rounds. */
export function createServerRuntime(authOptions: AuthenticatorOptions = {}): ServerRuntime {
  const config = resettable<Config>(() => loadConfig());
  const auth = resettable(() => new Authenticator(config(), authOptions));
  return { config, auth };
}

function argumentFingerprint(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("base64url");
}

function isSignInRequestState(value: unknown): value is SignInRequestState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const state = value as Record<string, unknown>;
  return (
    state.version === 1 &&
    (state.purpose === "xdr-login" || state.purpose === "xdr-run-query") &&
    typeof state.attemptId === "string" &&
    typeof state.flowId === "string" &&
    typeof state.tenantId === "string" &&
    typeof state.clientId === "string" &&
    typeof state.argumentFingerprint === "string"
  );
}

function consumeSignInFlow(flowId: string): void {
  const now = Date.now();
  for (const [id, expiresAt] of consumedSignInFlows) {
    if (expiresAt <= now) consumedSignInFlows.delete(id);
  }
  if (consumedSignInFlows.has(flowId)) throw new Error("This Defender XDR sign-in response was already consumed.");
  consumedSignInFlows.set(flowId, now + SIGN_IN_TIMEOUT_MS);
}

function serialize(value: unknown): string {
  const text = JSON.stringify(value, null, 2);
  if (Buffer.byteLength(text, "utf8") <= MAX_OUTPUT_BYTES) return text;
  // Truncated output is deliberately left as invalid JSON with a notice, so a prefix is
  // never mistaken for a complete result set.
  const head = new TextDecoder("utf8").decode(Buffer.from(text, "utf8").subarray(0, MAX_OUTPUT_BYTES));
  return `${head.replace(/�$/, "")}\n\n[Output truncated. Narrow the query, lower max_rows, or set export_results.]`;
}

const ok = (text: string) => ({ content: [{ type: "text" as const, text }] });
const failed = (error: unknown) => ({
  content: [{ type: "text" as const, text: error instanceof Error ? error.message : String(error) }],
  isError: true,
});

/** Graph annotates typed values with sibling `<field>@odata.type` keys that carry no signal. */
function stripAnnotations(row: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(row).filter(([key]) => !key.endsWith("@odata.type")));
}

/** Either the tenant answered, or it did not and said why. */
type Verification = { live: LiveColumns } | { unavailable: string };

/** How the live lookup went, for the payload: when it happened, or why it did not. */
function describeVerification(verified: Verification) {
  return "live" in verified
    ? {
        verifiedAt: verified.live.fetchedAt,
        fromCache: verified.live.cached,
        tenantColumns: verified.live.columns.length,
      }
    : {
        status: "unavailable",
        reason: verified.unavailable,
        note: "The columns above are from the bundled documentation snapshot, which can lag your tenant.",
      };
}

/** Writes untruncated results to an owner-only file, only when explicitly requested. */
async function exportResults(payload: unknown): Promise<string> {
  const directory = join(stateDir(), "exports");
  await makeOwnerOnlyDir(directory);
  // Colons and dots come out of the timestamp because Windows forbids them in file names.
  const path = join(directory, `hunting-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID()}.json`);
  await writeOwnerOnlyFile(path, `${JSON.stringify(payload, null, 2)}\n`);
  return path;
}

function supportsUrlElicitation(ctx: ServerContext): boolean {
  const envelope = ctx.mcpReq.envelope as Record<string, unknown> | undefined;
  const capabilities = envelope?.[CLIENT_CAPABILITIES_META_KEY] as ClientCapabilities | undefined;
  return capabilities?.elicitation?.url !== undefined;
}

export interface CreateServerOptions {
  runtime?: ServerRuntime;
  authenticator?: AuthenticatorOptions;
}

export function createServer(): McpServer;
export function createServer(options: CreateServerOptions): McpServer;
export function createServer(options: CreateServerOptions = {}): McpServer {
  const runtime = options.runtime ?? createServerRuntime(options.authenticator);
  const { config, auth } = runtime;
  const server = new McpServer(
    { name: manifest.name, version: manifest.version },
    { requestState: { verify: signInStateCodec.verify } },
  );

  function signInRequest(
    attempt: { authorizationUrl: string },
    requestState: string,
  ): InputRequiredResult {
    return inputRequired({
      inputRequests: {
        [SIGN_IN_RESPONSE_KEY]: inputRequired.elicitUrl({
          message: "Sign in to Microsoft Defender XDR, then confirm when you are done.",
          url: attempt.authorizationUrl,
        }),
      },
      requestState,
    });
  }

  async function beginSignIn(
    purpose: SignInPurpose,
    fingerprint: string,
    ctx: ServerContext,
  ): Promise<{ username: string } | { result: InputRequiredResult }> {
    const resolved = config();
    const attempt = await auth().startSignIn();
    const state: SignInRequestState = {
      version: 1,
      purpose,
      attemptId: attempt.attemptId,
      flowId: randomUUID(),
      tenantId: resolved.tenantId,
      clientId: resolved.clientId,
      argumentFingerprint: fingerprint,
    };

    if (supportsUrlElicitation(ctx)) {
      return { result: signInRequest(attempt, await signInStateCodec.mint(state, ctx)) };
    }

    auth().openSignInInBrowser(attempt.attemptId);
    return { username: await auth().waitForSignIn(attempt.attemptId) };
  }

  async function resumeSignIn(
    value: unknown,
    purpose: SignInPurpose,
    fingerprint: string,
    ctx: ServerContext,
  ): Promise<{ username: string } | { result: InputRequiredResult }> {
    if (!isSignInRequestState(value)) throw new Error("The Defender XDR sign-in request state is malformed.");
    if (value.purpose !== purpose || value.argumentFingerprint !== fingerprint) {
      throw new Error("The Defender XDR sign-in request does not match this tool call.");
    }

    const resolved = config();
    if (value.tenantId !== resolved.tenantId || value.clientId !== resolved.clientId) {
      throw new Error("The Defender XDR sign-in request no longer matches the configured tenant or application.");
    }

    const attempt = auth().signInAttempt(value.attemptId);
    if (!attempt) throw new Error("The Defender XDR sign-in attempt is unknown or expired.");

    const response = inputResponse(ctx.mcpReq.inputResponses, SIGN_IN_RESPONSE_KEY);
    if (response.kind === "missing") {
      return { result: signInRequest(attempt, await signInStateCodec.mint(value, ctx)) };
    }

    consumeSignInFlow(value.flowId);
    if (response.kind !== "elicit") {
      throw new Error("The Defender XDR sign-in response was malformed.");
    }
    if (response.action === "decline" || response.action === "cancel") {
      const reason = response.action === "decline" ? "Sign-in was declined." : "Sign-in was cancelled.";
      auth().cancelSignIn(value.attemptId, reason);
      throw new Error(reason);
    }
    return { username: await auth().waitForSignIn(value.attemptId) };
  }

  /**
   * Answers a rejected query with the columns the tenant really has, so correcting the KQL
   * never needs a separate schema round-trip. Live columns only: a rejection is often exactly
   * the place where the documentation was wrong, so documented columns are not offered here.
   * A retired table's replacement rides along, because that is the table the corrected query
   * should read. Anything that cannot be answered is skipped rather than reported.
   */
  async function rejectedQueryHelp(query: string): Promise<string> {
    const tables = referencedTables(query, tableNames()).slice(0, 4);
    for (const name of [...tables]) {
      const replacement = findTable(name)?.replacedBy;
      if (replacement && !tables.some(other => other.toLowerCase() === replacement.toLowerCase())) {
        tables.push(replacement);
      }
    }

    const lines: string[] = [];
    for (const name of tables) {
      const documented = findTable(name);
      const note = documented?.replacedBy ? ` (retired, replaced by ${documented.replacedBy})` : "";
      try {
        const live = await liveColumns(auth(), config(), name);
        const columns = live.columns.map(column => (column.type ? `${column.name} (${column.type})` : column.name));
        lines.push(`${documented?.name ?? name}${note}: ${columns.join(", ")}`);
      } catch {
        // The table itself may be what the tenant rejected; its retirement is still worth saying.
        if (note) lines.push(`${documented!.name}${note}`);
      }
    }
    if (lines.length === 0) return "";
    return `\n\nThe tenant's columns for the tables this query referenced:\n${lines.join("\n")}`;
  }

  server.registerTool(
    "xdr_login",
    {
      title: "Sign in to Defender XDR",
      description:
        "Sign in to Microsoft Defender XDR in the browser. Querying signs in on its own, so this is only needed to configure the plugin (pass tenant_id and client_id, which are saved and applied immediately), to switch tenant or account, or to sign in ahead of time. Returns once the user finishes signing in.",
      inputSchema: z.object({
        tenant_id: z
          .string()
          .optional()
          .describe("GUID of the Entra tenant to query. Only needed the first time, or to change tenants."),
        client_id: z
          .string()
          .optional()
          .describe(
            "GUID of the Entra app registration to sign in with. Only needed the first time. This is not a secret.",
          ),
      }),
    },
    async ({ tenant_id, client_id }, ctx) => {
      try {
        const fingerprint = argumentFingerprint({ tenant_id, client_id });
        const state = ctx.mcpReq.requestState<unknown>();
        let signIn: { username: string } | { result: InputRequiredResult };

        if (state !== undefined) {
          // Resume before configuration work. Re-saving and resetting here would discard the
          // authenticator that owns the pending loopback listener.
          signIn = await resumeSignIn(state, "xdr-login", fingerprint, ctx);
        } else {
          if (tenant_id || client_id) {
            // Either ID may be supplied alone to correct just that one, so the missing half
            // comes from what was saved before. saveStoredConfig validates both.
            const saved = readStoredConfig();
            await saveStoredConfig({
              tenantId: tenant_id ?? saved.tenantId ?? "",
              clientId: client_id ?? saved.clientId ?? "",
            });
            // A new tenant or app makes the resolved config and any cached token stale.
            config.reset();
            auth.reset();
          }
          // Explicit login always starts an account-selection flow, even with a usable token.
          signIn = await beginSignIn("xdr-login", fingerprint, ctx);
        }

        if ("result" in signIn) return signIn.result;
        return ok(
          `Signed in to Defender XDR as ${signIn.username}. Queries will reuse this sign-in until it expires or is revoked.`,
        );
      } catch (error) {
        return failed(error);
      }
    },
  );

  server.registerTool(
    "xdr_logout",
    {
      title: "Sign out of Defender XDR",
      description:
        "Delete the Defender XDR sign-in cached on this machine, along with any tenant schema cached from it. This does not revoke the Entra session in the browser or sign the user out of other applications.",
      inputSchema: z.object({}),
    },
    async () => {
      const [removed, cacheRemoved] = await Promise.all([clearStoredToken(), clearLiveCache()]);
      return ok(
        (removed
          ? "Removed the cached Defender XDR sign-in from this machine. The browser session with Microsoft is untouched."
          : "No Defender XDR sign-in was cached on this machine.") +
          (cacheRemoved ? " The cached tenant schema was deleted as well." : ""),
      );
    },
  );

  server.registerTool(
    "xdr_run_query",
    {
      title: "Run a Defender XDR hunting query",
      description:
        "Run a read-only KQL query against Microsoft Defender XDR Advanced Hunting and return the rows. Advanced Hunting cannot modify tenant state. Signs the user in through their browser automatically on first use, so call this directly rather than signing in first. A rejected query reports the columns the tenant really has for the tables it referenced, so correct the KQL from that answer instead of guessing again.",
      inputSchema: z.object({
        query: z.string().describe("The KQL Advanced Hunting query to run"),
        timespan: z
          .string()
          .optional()
          .describe("Lookback window such as 7d, 24h, P7D, or PT24H. Defaults to the configured window."),
        max_rows: z.number().int().min(1).max(10000).optional().describe("Rows to return, capped by the configured maximum"),
        export_results: z
          .boolean()
          .optional()
          .describe("Write the complete, untruncated result set to an owner-only local file"),
      }),
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ query, timespan, max_rows, export_results }, ctx) => {
      try {
        const fingerprint = argumentFingerprint({ query, timespan, max_rows, export_results });
        const state = ctx.mcpReq.requestState<unknown>();
        if (state !== undefined) {
          const signIn = await resumeSignIn(state, "xdr-run-query", fingerprint, ctx);
          if ("result" in signIn) return signIn.result;
        } else {
          try {
            await auth().accessTokenSilent();
          } catch (error) {
            if (!(error instanceof NotSignedInError)) throw error;
            const signIn = await beginSignIn("xdr-run-query", fingerprint, ctx);
            if ("result" in signIn) return signIn.result;
          }
        }

        const resolved = config();
        const result = await runHuntingQuery(auth(), resolved, {
          query,
          timespan: timespan ?? resolved.defaultTimespan,
        });

        // Record what this tenant reports for the tables the query read, so the next schema
        // question is answered from the tenant rather than from documentation that may be months
        // old. Investigations start with a question, not a schema lookup, so waiting for someone
        // to call xdr_get_schema first left the cache empty exactly when it was needed.
        //
        // Deliberately not awaited: the rows the user asked for should not wait on it. Tables
        // still inside their TTL cost nothing, so a repeated query makes no extra calls.
        void warmTables(auth(), resolved, referencedTables(query, tableNames()));

        // The configured maximum is a ceiling the caller cannot raise.
        const limit = Math.min(max_rows ?? resolved.maxRows, resolved.maxRows);
        const rows = result.results.slice(0, limit).map(stripAnnotations);

        let text = serialize({
          totalRows: result.results.length,
          returnedRows: rows.length,
          truncated: rows.length < result.results.length,
          // With no rows to infer from, the column list is the only useful signal.
          ...(rows.length === 0 ? { columns: result.schema } : {}),
          rows,
        });
        if (export_results) {
          text += `\n\n[Complete results written to ${await exportResults(result)}]`;
        }
        return ok(text);
      } catch (error) {
        // A rejection is usually a table or column this tenant does not have, so the error
        // carries the tenant's own columns and the model can correct in one step. When no
        // table could be identified or asked, fall back to naming the schema tool.
        if (error instanceof GraphRequestError && error.status === 400) {
          // Abandoned help keeps probing in the background and still lands in the cache,
          // so the model's retry finds the columns even when this error went out bare.
          const help = await Promise.race([
            rejectedQueryHelp(query).catch(() => ""),
            new Promise<string>(resolve => setTimeout(() => resolve(""), REJECTED_HELP_TIMEOUT_MS).unref()),
          ]);
          return failed(
            new Error(
              error.message +
                (help || "; if a table or column may not exist in this tenant, check it with xdr_get_schema"),
            ),
          );
        }
        return failed(error);
      }
    },
  );

  /**
   * Asks the tenant which columns a table really has, or explains why it could not.
   *
   * A failure here is never fatal: an unconfigured plugin, a signed-out user, or a table this
   * tenant does not carry all degrade to the bundled snapshot with the reason attached. That is
   * more useful than an error, and it cannot interrupt the user with a browser sign-in.
   */
  async function verifyAgainstTenant(table: string, refresh: boolean): Promise<Verification> {
    try {
      return { live: await liveColumns(auth(), config(), table, { refresh }) };
    } catch (error) {
      // The full "not configured" message asks Claude to go collect two GUIDs, which is the
      // wrong thing to chase in the middle of a schema lookup, so it is condensed here.
      if (error instanceof NotConfiguredError) return { unavailable: "the plugin is not configured yet" };
      return { unavailable: error instanceof Error ? error.message : String(error) };
    }
  }

  /** The signed-in tenant, when there is one — schema lookups work unconfigured too. */
  function tenantId(): string | undefined {
    try {
      return config().tenantId;
    } catch {
      return undefined;
    }
  }

  server.registerTool(
    "xdr_get_schema",
    {
      title: "Look up Defender XDR tables and columns",
      description:
        "List, search, or describe Defender XDR Advanced Hunting tables and their columns. Describing an exact table also verifies its columns against the signed-in tenant with a zero-row query, cached for a week, so tenant-specific, preview, and newly added columns show up next to the bundled documentation; pass live=false to stay offline. Listing and searching read local files only. Use it before writing a query that leans on an uncertain table or column.",
      inputSchema: z.object({
        table: z.string().optional().describe("Exact table name to describe, such as DeviceProcessEvents"),
        search: z.string().optional().describe("Substring to match against table and column names and descriptions"),
        include_retired: z.boolean().optional().describe("Include tables Microsoft has retired"),
        live: z
          .boolean()
          .optional()
          .describe(
            "Verify an exact table's columns against the signed-in tenant. Defaults to true; pass false for the bundled documentation alone.",
          ),
        refresh: z
          .boolean()
          .optional()
          .describe("Ignore the cached tenant columns for this table and ask the tenant again"),
      }),
      annotations: { readOnlyHint: true },
    },
    async ({ table, search, include_retired = false, live = true, refresh = false }) => {
      try {
        if (table && search) throw new Error("Pass either table or search, not both");
        if (refresh && !table) throw new Error("refresh applies only to an exact table");

        if (table) {
          const documented = findTable(table);
          const verified = live ? await verifyAgainstTenant(table, refresh) : undefined;
          const tenant = verified && "live" in verified ? verified.live : undefined;
          if (!documented && !tenant) {
            throw new Error(
              `Unknown Defender XDR table "${table}". Closest documented names: ${suggestTables(table).join(", ")}` +
                (verified && "unavailable" in verified
                  ? `. The tenant could not be asked: ${verified.unavailable}`
                  : ""),
            );
          }

          // A table the tenant returns but the documentation does not describe is still real —
          // a custom table, or one newer than the snapshot — so it is reported, not refused.
          const merged = tenant ? mergeColumns(documented?.columns ?? [], tenant.columns) : undefined;
          return ok(
            serialize({
              name: documented?.name ?? table,
              description:
                documented?.description ?? "Present in your tenant; absent from the bundled documentation snapshot.",
              status: documented?.status ?? "tenant-only",
              ...(documented?.replacedBy
                ? { replacedBy: documented.replacedBy, retirementDate: documented.retirementDate }
                : {}),
              ...(documented ? { documentationUrl: documented.documentationUrl } : {}),
              columns: merged?.columns ?? documented?.columns ?? [],
              // Documented columns the tenant did not return: retired, unlicensed, or not yet
              // rolled out here. Naming them stops a query being built on one of them.
              ...(merged?.documentedOnly.length ? { documentedNotInTenant: merged.documentedOnly } : {}),
              ...(verified ? { liveVerification: describeVerification(verified) } : {}),
            }),
          );
        }

        if (search) {
          const tenant = tenantId();
          const cachedTenantMatches = tenant ? await searchLiveCache(search, tenant) : [];
          return ok(
            serialize({
              search,
              matches: searchTables(search, include_retired),
              // Columns cached by an earlier live lookup, matched from disk: no query is sent,
              // and these can include columns the documentation snapshot has never heard of.
              ...(cachedTenantMatches.length ? { cachedTenantMatches } : {}),
            }),
          );
        }

        return ok(
          serialize({
            tables: listTables(include_retired),
            sourceDate: schema.sourceDate,
            sourceUrl: schema.sourceUrl,
          }),
        );
      } catch (error) {
        return failed(error);
      }
    },
  );

  return server;
}
