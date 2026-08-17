import { randomUUID } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { XdrAuth } from "./auth.js";
import { getXdrDirectory, loadConfig } from "./config.js";
import { runHuntingQuery } from "./client.js";
import { bounded, stripODataAnnotations } from "./output.js";
import { findSchemaTable, liveColumns, loadSchemaSnapshot, searchSchema } from "./schema.js";
const SERVER_VERSION = "0.1.0";
/** Writes the untruncated response to an owner-only file, only on explicit user request. */
async function exportResult(result) {
    const directory = join(getXdrDirectory(), "exports");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const path = join(directory, `hunting-${stamp}-${randomUUID()}.json`);
    await writeFile(path, `${JSON.stringify(result, null, 2)}\n`, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
    });
    await chmod(path, 0o600);
    return path;
}
function errorResult(error) {
    const text = error instanceof Error ? error.message : String(error);
    return {
        content: [{ type: "text", text: `Defender XDR error: ${text}` }],
        isError: true,
    };
}
function textResult(text) {
    return { content: [{ type: "text", text }] };
}
/**
 * Config and auth are resolved once and reused, but a *failed* attempt is not cached: the
 * usual fix (running the login command, or repairing the keychain) happens out of band
 * while this server keeps running, and the next tool call must see the repaired state.
 */
let configPromise;
let authPromise;
function memoize(get, read, write) {
    const existing = read();
    if (existing)
        return existing;
    const pending = get().catch(error => {
        write(undefined);
        throw error;
    });
    write(pending);
    return pending;
}
const config = () => memoize(() => loadConfig(), () => configPromise, value => (configPromise = value));
const auth = () => memoize(() => config().then(resolved => XdrAuth.create(resolved)), () => authPromise, value => (authPromise = value));
const server = new McpServer({
    name: "defender-xdr",
    version: SERVER_VERSION,
    description: "Read-only Microsoft Defender XDR Advanced Hunting via Microsoft Graph. Authentication is never started by tools; run claude-defender-xdr-login first.",
});
server.registerTool("xdr_run_query", {
    description: "Run a bounded, read-only KQL query against Microsoft Defender XDR Advanced Hunting. Never writes or changes tenant state. Use claude-defender-xdr-login when authentication is required.",
    inputSchema: {
        query: z.string().describe("Read-only KQL Advanced Hunting query"),
        timespan: z.string().optional().describe("7d, 24h, P7D, or PT24H"),
        max_rows: z.number().int().min(1).max(10000).optional(),
        export_results: z
            .boolean()
            .optional()
            .describe("Save complete results locally only when explicitly requested"),
    },
}, async ({ query, timespan, max_rows, export_results }) => {
    try {
        const [xdrConfig, xdrAuth] = await Promise.all([config(), auth()]);
        const result = await runHuntingQuery(xdrAuth, xdrConfig, {
            query,
            ...(timespan ? { timespan } : {}),
        });
        // The configured maximum is a ceiling the caller cannot raise.
        const limit = Math.min(max_rows ?? xdrConfig.maximumRows, xdrConfig.maximumRows);
        const rows = result.results.slice(0, limit).map(stripODataAnnotations);
        let text = bounded({
            totalRows: result.results.length,
            displayedRows: rows.length,
            rowsTruncated: rows.length < result.results.length,
            // With no rows to infer from, the column list is the only useful signal.
            ...(rows.length === 0 ? { schema: result.schema } : {}),
            results: rows,
        });
        if (export_results) {
            const path = await exportResult({ schema: result.schema, results: result.results });
            text += `\n\n[Complete owner-only result exported to ${path}]`;
        }
        return textResult(text);
    }
    catch (error) {
        return errorResult(error);
    }
});
server.registerTool("xdr_get_schema", {
    description: "List, search, or describe Defender XDR Advanced Hunting tables and columns from the bundled official schema snapshot. Optionally verify an exact table against the tenant with take 0.",
    inputSchema: {
        table: z.string().optional(),
        search: z.string().optional(),
        live: z.boolean().optional(),
        include_retired: z.boolean().optional(),
        verbose: z.boolean().optional(),
    },
}, async ({ table, search, live, include_retired, verbose }) => {
    try {
        if (table && search)
            throw new Error("Specify either table or search, not both");
        if (live && !table)
            throw new Error("live requires an exact table");
        const snapshot = await loadSchemaSnapshot();
        if (table) {
            const found = await findSchemaTable(table);
            if (!found) {
                const suggestions = searchSchema(snapshot, table, true, 5)
                    .map(match => match.table)
                    .join(", ");
                throw new Error(`Unknown Defender XDR table ${JSON.stringify(table)}; possible matches: ${suggestions}`);
            }
            if (found.status === "retired" && !include_retired) {
                throw new Error(`${found.name} retired${found.replacedBy ? `; use ${found.replacedBy}` : ""}`);
            }
            let payload = {
                name: found.name,
                description: found.description,
                status: found.status,
                ...(found.replacedBy
                    ? { replacedBy: found.replacedBy, retirementDate: found.retirementDate }
                    : {}),
                ...(verbose ? { documentationUrl: found.documentationUrl } : {}),
                columns: found.columns.map(column => verbose ? column : { name: column.name, type: column.type }),
            };
            if (live) {
                const [xdrConfig, xdrAuth] = await Promise.all([config(), auth()]);
                const verified = await liveColumns(found, xdrAuth, xdrConfig);
                payload = {
                    ...payload,
                    columns: verified.columns,
                    liveVerification: { fetchedAt: verified.fetchedAt },
                };
            }
            return textResult(bounded(payload));
        }
        if (search) {
            return textResult(bounded({ search, matches: searchSchema(snapshot, search, include_retired) }));
        }
        return textResult(bounded({
            tables: snapshot.tables
                .filter(entry => include_retired || entry.status !== "retired")
                .map(({ name, description, status, replacedBy }) => ({
                name,
                description,
                status,
                ...(replacedBy ? { replacedBy } : {}),
            })),
            sourceDate: snapshot.sourceDate,
            sourceUrl: snapshot.sourceUrl,
        }));
    }
    catch (error) {
        return errorResult(error);
    }
});
await server.connect(new StdioServerTransport());
//# sourceMappingURL=index.js.map