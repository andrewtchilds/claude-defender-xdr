import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { Authenticator, clearStoredToken } from "./auth.js";
import {
  loadConfig,
  makeOwnerOnlyDir,
  readStoredConfig,
  saveStoredConfig,
  stateDir,
  writeOwnerOnlyFile,
  type Config,
} from "./config.js";
import { runHuntingQuery } from "./graph.js";
import { findTable, listTables, schema, searchTables, suggestTables } from "./schema.js";

/** Keeps one tool result well inside the model's context budget. */
const MAX_OUTPUT_BYTES = 50 * 1024;

/**
 * Configuration and the authenticator are resolved on first use rather than at startup,
 * so the server still connects (and `xdr_get_schema` still answers) when the plugin has
 * not been configured yet. Only a successful resolution is cached, and `reset` drops it,
 * so configuring through `xdr_login` applies to the very next call without a restart.
 */
function resettable<T>(create: () => T) {
  let cached: T | undefined;
  const get = () => (cached ??= create());
  get.reset = () => {
    cached = undefined;
  };
  return get;
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
  await makeOwnerOnlyDir(directory);
  // Colons and dots come out of the timestamp because Windows forbids them in file names.
  const path = join(directory, `hunting-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID()}.json`);
  await writeOwnerOnlyFile(path, `${JSON.stringify(payload, null, 2)}\n`);
  return path;
}

export function createServer(): McpServer {
  const server = new McpServer({ name: "defender-xdr", version: "1.0.0" });

  const config = resettable<Config>(() => loadConfig());
  const auth = resettable(() => new Authenticator(config()));

  server.registerTool(
    "xdr_login",
    {
      title: "Sign in to Defender XDR",
      description:
        "Sign in to Microsoft Defender XDR in the system browser. Querying signs in on its own, so this is only needed to configure the plugin (pass tenant_id and client_id, which are saved and applied immediately), to switch tenant or account, or to sign in ahead of time. Returns once the user finishes signing in.",
      inputSchema: {
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
      },
    },
    async ({ tenant_id, client_id }) => {
      try {
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
        "Run a read-only KQL query against Microsoft Defender XDR Advanced Hunting and return the rows. Advanced Hunting cannot modify tenant state. Signs the user in through their browser automatically on first use, so call this directly rather than signing in first.",
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
