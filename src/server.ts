import { randomUUID } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { Authenticator, clearStoredToken } from "./auth.js";
import { loadConfig, stateDir, type Config } from "./config.js";
import { runHuntingQuery } from "./graph.js";
import { findTable, listTables, schema, searchTables, suggestTables } from "./schema.js";

/** Keeps one tool result well inside the model's context budget. */
const MAX_OUTPUT_BYTES = 50 * 1024;

/**
 * Configuration and the authenticator are resolved on first use rather than at startup,
 * so the server still connects (and `xdr_get_schema` still answers) when the plugin has
 * not been configured yet. Only a successful resolution is cached: after the user fixes
 * the configuration and restarts, the next call must see the repaired state.
 */
function lazily<T>(create: () => T): () => T {
  let cached: T | undefined;
  return () => (cached ??= create());
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

/** Writes untruncated results to an owner-only file, only when explicitly requested. */
async function exportResults(payload: unknown): Promise<string> {
  const directory = join(stateDir(), "exports");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700).catch(() => undefined);
  const path = join(directory, `hunting-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID()}.json`);
  await writeFile(path, `${JSON.stringify(payload, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await chmod(path, 0o600).catch(() => undefined);
  return path;
}

export function createServer(): McpServer {
  const server = new McpServer({ name: "defender-xdr", version: "1.0.0" });

  const config = lazily<Config>(() => loadConfig());
  const auth = lazily(() => new Authenticator(config()));

  server.registerTool(
    "xdr_login",
    {
      title: "Sign in to Defender XDR",
      description:
        "Open the system browser and sign in to Microsoft Defender XDR. Call this when a query reports that no sign-in is cached. Returns once the user finishes signing in; the refresh token is then reused, so this is normally needed only once.",
      inputSchema: {},
    },
    async () => {
      try {
        const username = await auth().signIn();
        return ok(`Signed in to Defender XDR as ${username}. Queries will reuse this sign-in until it expires or is revoked.`);
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
        "Delete the Defender XDR sign-in cached on this machine. This does not revoke the Entra session in the browser or sign the user out of other applications.",
      inputSchema: {},
    },
    async () => {
      const removed = await clearStoredToken();
      return ok(
        removed
          ? "Removed the cached Defender XDR sign-in from this machine. The browser session with Microsoft is untouched."
          : "No Defender XDR sign-in was cached on this machine.",
      );
    },
  );

  server.registerTool(
    "xdr_run_query",
    {
      title: "Run a Defender XDR hunting query",
      description:
        "Run a read-only KQL query against Microsoft Defender XDR Advanced Hunting and return the rows. Advanced Hunting cannot modify tenant state. If it reports that no sign-in is cached, call xdr_login and retry.",
      inputSchema: {
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
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ query, timespan, max_rows, export_results }) => {
      try {
        const resolved = config();
        const result = await runHuntingQuery(auth(), resolved, {
          query,
          timespan: timespan ?? resolved.defaultTimespan,
        });

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
        return failed(error);
      }
    },
  );

  server.registerTool(
    "xdr_get_schema",
    {
      title: "Look up Defender XDR tables and columns",
      description:
        "List, search, or describe Defender XDR Advanced Hunting tables and their columns from the bundled official schema. Works without signing in. Use it before writing a query that relies on an uncertain table or column.",
      inputSchema: {
        table: z.string().optional().describe("Exact table name to describe, such as DeviceProcessEvents"),
        search: z.string().optional().describe("Substring to match against table and column names and descriptions"),
        include_retired: z.boolean().optional().describe("Include tables Microsoft has retired"),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ table, search, include_retired = false }) => {
      try {
        if (table && search) throw new Error("Pass either table or search, not both");

        if (table) {
          const found = findTable(table);
          if (!found) {
            throw new Error(
              `Unknown Defender XDR table "${table}". Closest names: ${suggestTables(table).join(", ")}`,
            );
          }
          return ok(
            serialize({
              name: found.name,
              description: found.description,
              status: found.status,
              ...(found.replacedBy
                ? { replacedBy: found.replacedBy, retirementDate: found.retirementDate }
                : {}),
              documentationUrl: found.documentationUrl,
              columns: found.columns,
            }),
          );
        }

        if (search) {
          return ok(serialize({ search, matches: searchTables(search, include_retired) }));
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
