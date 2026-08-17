import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runHuntingQuery } from "./client.js";
const DEFAULT_SEARCH_LIMIT = 20;
const SNAPSHOT_RELATIVE_PATH = join("schema-snapshot", "defender-xdr-schema.json");
/**
 * The snapshot ships at `<plugin root>/schema-snapshot/`. CLAUDE_PLUGIN_ROOT is the
 * authoritative location when Claude Code launches the server; walking up from this module
 * covers everything else, since the depth differs between `server/` (tests, run from
 * source) and `dist/server/` (the published build).
 */
function snapshotCandidates() {
    const paths = [];
    if (process.env.CLAUDE_PLUGIN_ROOT) {
        paths.push(join(process.env.CLAUDE_PLUGIN_ROOT, SNAPSHOT_RELATIVE_PATH));
    }
    let directory = dirname(fileURLToPath(import.meta.url));
    for (let depth = 0; depth < 4; depth++) {
        paths.push(join(directory, SNAPSHOT_RELATIVE_PATH));
        const parent = dirname(directory);
        if (parent === directory)
            break;
        directory = parent;
    }
    return paths;
}
async function readSnapshot() {
    const candidates = snapshotCandidates();
    for (const path of candidates) {
        let text;
        try {
            text = await readFile(path, "utf8");
        }
        catch (error) {
            if (error.code === "ENOENT")
                continue;
            throw error;
        }
        return validate(JSON.parse(text));
    }
    throw new Error(`Bundled Defender XDR schema snapshot not found. Looked in: ${candidates.join(", ")}`);
}
let snapshot;
export function loadSchemaSnapshot() {
    snapshot ??= readSnapshot().catch(error => {
        snapshot = undefined; // Allow a later call to retry rather than caching the failure.
        throw error;
    });
    return snapshot;
}
export async function findSchemaTable(name) {
    const wanted = name.trim().toLowerCase();
    return (await loadSchemaSnapshot()).tables.find(table => table.name.toLowerCase() === wanted);
}
export function searchSchema(snapshot, term, includeRetired = false, limit = DEFAULT_SEARCH_LIMIT) {
    const needle = term.trim().toLowerCase();
    if (!needle)
        return [];
    const columnMatches = (column) => `${column.name} ${column.description}`.toLowerCase().includes(needle);
    return snapshot.tables
        .filter(table => includeRetired || table.status !== "retired")
        .filter(table => `${table.name} ${table.description}`.toLowerCase().includes(needle) ||
        table.columns.some(columnMatches))
        .slice(0, limit)
        .map(table => ({
        table: table.name,
        tableDescription: table.description,
        status: table.status,
        matchingColumns: table.columns.filter(columnMatches).slice(0, DEFAULT_SEARCH_LIMIT),
    }));
}
/** Confirms a table exists in this tenant and returns its real columns, without reading rows. */
export async function liveColumns(table, auth, config, signal) {
    const result = await runHuntingQuery(auth, config, { query: `${table.name}\n| take 0`, timespan: config.defaultLookback }, signal);
    return { columns: result.schema, fetchedAt: new Date().toISOString() };
}
function validate(value) {
    const invalid = () => new Error("Bundled Defender XDR schema snapshot is invalid");
    if (!value || typeof value !== "object")
        throw invalid();
    const tables = value.tables;
    if (!Array.isArray(tables) || tables.length === 0)
        throw invalid();
    const wellFormed = tables.every(table => table &&
        typeof table === "object" &&
        typeof table.name === "string" &&
        Array.isArray(table.columns));
    if (!wellFormed)
        throw invalid();
    return value;
}
//# sourceMappingURL=schema.js.map