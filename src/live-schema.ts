/**
 * The tenant's own view of a table, cached on disk.
 *
 * The bundled snapshot is compiled from Microsoft's published documentation, so it is always a
 * little behind the product: preview columns reach a tenant before they are documented, retired
 * ones linger in the docs, licensing changes what a given tenant returns, and custom tables
 * never appear in the docs at all. Asking the tenant costs one zero-row query, so the answer is
 * cached per table and reused instead of being re-asked on every lookup.
 */

import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import type { Authenticator } from "./auth.js";
import { saveOwnerOnlyJson, stateDir, type Config } from "./config.js";
import { runHuntingQuery } from "./graph.js";
import type { SchemaColumn } from "./schema.js";

/** How long a cached column list is trusted before the tenant is asked again. */
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Table names are interpolated into KQL, so only the shape Advanced Hunting actually uses is
 * accepted — a letter or underscore, then letters, digits, and underscores. Anything else is
 * refused before a query is built, rather than escaped and sent.
 */
const TABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/**
 * Words a query can open with that name no table: KQL operators and tabular-expression
 * producers. Probing one of these would spend a call to learn that `let` is not a table.
 */
const NOT_A_TABLE = new Set([
  "alias", "cluster", "database", "datatable", "declare", "evaluate", "externaldata", "find",
  "join", "let", "materialize", "print", "range", "search", "set", "toscalar", "union",
]);

/** Said of a live column the bundled documentation has nothing to say about. */
export const UNDOCUMENTED = "Not in the bundled documentation snapshot";

/** Advanced Hunting reports a column as a name and a type, with no description. */
export interface LiveColumn {
  name: string;
  type?: string;
}

interface CachedTable {
  /** The name as Microsoft spells it, since the cache is keyed case-insensitively. */
  name: string;
  fetchedAt: string;
  columns: LiveColumn[];
}

interface Cache {
  version: 1;
  /** Columns are tenant-specific, so a cache minted for another tenant is dropped, not merged. */
  tenantId: string;
  tables: Record<string, CachedTable>;
}

export interface LiveColumns {
  columns: LiveColumn[];
  fetchedAt: string;
  /** True when the columns came from disk, so the caller can say how fresh they are. */
  cached: boolean;
}

export function liveCachePath(env: NodeJS.ProcessEnv = process.env): string {
  return join(stateDir(env), "schema-cache.json");
}

/**
 * Reads the cache for one tenant. Anything unusable — missing, damaged, an older layout, or
 * another tenant's columns — reads as empty, because a cache is always cheaper to rebuild than
 * to repair, and serving a different tenant's columns would be worse than serving none.
 */
async function readCache(tenantId: string, env: NodeJS.ProcessEnv): Promise<Cache> {
  const empty: Cache = { version: 1, tenantId, tables: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(liveCachePath(env), "utf8"));
  } catch {
    return empty;
  }
  if (!parsed || typeof parsed !== "object") return empty;
  const { version, tenantId: cachedTenant, tables } = parsed as Partial<Cache>;
  if (version !== 1 || cachedTenant !== tenantId) return empty;
  if (!tables || typeof tables !== "object" || Array.isArray(tables)) return empty;
  return { version: 1, tenantId, tables };
}

/**
 * Returns the columns the signed-in tenant reports for one table, from cache when it is fresh.
 *
 * The fetch is `TableName | take 0`: it returns the table's full column list and no rows at
 * all, which is the cheapest question that still reflects what this tenant really has.
 */
export async function liveColumns(
  auth: Authenticator,
  config: Config,
  table: string,
  options: { refresh?: boolean; env?: NodeJS.ProcessEnv } = {},
): Promise<LiveColumns> {
  const name = table.trim();
  if (!TABLE_NAME.test(name)) {
    throw new Error(`"${table}" is not a Defender XDR table name, so the tenant was not asked`);
  }

  const env = options.env ?? process.env;
  const cache = await readCache(config.tenantId, env);
  const key = name.toLowerCase();
  const cached = cache.tables[key];
  // Date.parse returns NaN for a damaged timestamp, and NaN fails this comparison, so a
  // hand-edited or truncated entry refetches instead of being trusted forever.
  if (!options.refresh && cached && Date.now() - Date.parse(cached.fetchedAt) < CACHE_TTL_MS) {
    return { columns: cached.columns, fetchedAt: cached.fetchedAt, cached: true };
  }

  // Silent auth only: looking up a schema must never pop open a browser sign-in the user did
  // not ask for. Not being signed in surfaces as an error the caller degrades to the snapshot.
  const result = await runHuntingQuery(auth, config, {
    query: `${name}\n| take 0`,
    timespan: config.defaultTimespan,
    silent: true,
  });

  const fetchedAt = new Date().toISOString();
  cache.tables[key] = { name, fetchedAt, columns: result.schema };
  // Two lookups racing here can leave one table out of the file, since each writes the whole
  // cache it read. That costs a refetch later and nothing else, which is cheaper than locking.
  // A write that fails outright — on Windows, a scanner can hold the file locked past every
  // retry — costs the same refetch, and must not cost the columns that were just fetched.
  await saveOwnerOnlyJson(liveCachePath(env), cache).catch(() => undefined);
  return { columns: result.schema, fetchedAt, cached: false };
}

/**
 * Searches columns already cached from the tenant.
 *
 * This reads local files only and never submits a query, which is what makes it safe to run
 * alongside every snapshot search: a column that exists in the tenant but not in the docs is
 * findable as soon as anything has described its table once.
 */
export async function searchLiveCache(
  term: string,
  tenantId: string,
  env: NodeJS.ProcessEnv = process.env,
  limit = 20,
): Promise<{ table: string; fetchedAt: string; matchingColumns: LiveColumn[] }[]> {
  const terms = term.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [];
  const matchesAll = (haystack: string) => terms.every(needle => haystack.includes(needle));

  const cache = await readCache(tenantId, env);
  return Object.values(cache.tables)
    .map(table => ({
      table: table.name,
      fetchedAt: table.fetchedAt,
      matchingColumns: table.columns.filter(column => matchesAll(column.name.toLowerCase())),
    }))
    .filter(match => match.matchingColumns.length > 0 || matchesAll(match.table.toLowerCase()))
    .sort((a, b) => b.matchingColumns.length - a.matchingColumns.length)
    .slice(0, limit);
}

/**
 * Combines what the tenant returns with what the documentation says.
 *
 * The tenant decides which columns exist — that is the whole point of asking it — while the
 * snapshot supplies the prose, which is the one thing it is better at. Documented columns the
 * tenant did not return are listed separately rather than dropped, because their absence is
 * itself an answer: retired, not licensed, or not yet rolled out.
 */
export function mergeColumns(
  documented: SchemaColumn[],
  live: LiveColumn[],
): { columns: SchemaColumn[]; documentedOnly: string[] } {
  const byName = new Map(documented.map(column => [column.name.toLowerCase(), column]));
  const liveNames = new Set(live.map(column => column.name.toLowerCase()));
  return {
    columns: live.map(column => {
      const match = byName.get(column.name.toLowerCase());
      return {
        name: column.name,
        type: column.type ?? match?.type ?? "unknown",
        description: match?.description ?? UNDOCUMENTED,
      };
    }),
    documentedOnly: documented.filter(column => !liveNames.has(column.name.toLowerCase())).map(column => column.name),
  };
}

/**
 * Names the tables a query reads from.
 *
 * Two rules, both deliberately conservative. A name already known to be a table counts wherever
 * it appears, even inside a string, because the worst case is one probe of a table that really
 * exists. Everything else has to sit in a position only a table can occupy, since a custom table
 * appears in no snapshot and position is the only evidence that it is a table at all.
 *
 * Missing a table here is cheap: the schema tool still probes on demand. Inventing one is not,
 * so the rules stay narrow rather than clever.
 */
export function referencedTables(query: string, documented: Iterable<string> = []): string[] {
  const canonical = new Map([...documented].map(name => [name.toLowerCase(), name]));
  const found = new Map<string, string>();
  const add = (name: string | undefined) => {
    if (!name || !TABLE_NAME.test(name) || NOT_A_TABLE.has(name.toLowerCase())) return;
    found.set(name.toLowerCase(), canonical.get(name.toLowerCase()) ?? name);
  };

  for (const [word] of query.matchAll(/[A-Za-z_][A-Za-z0-9_]*/g)) {
    if (canonical.has(word.toLowerCase())) add(word);
  }
  // The three shapes a table can appear in: opening the query, listed after union, or opening a
  // join's subquery. The optional `kind=leftouter` and `hint.strategy=shuffle` are stepped over.
  add(/^\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(query)?.[1]);
  for (const match of query.matchAll(/\bunion\s+(?:[\w.]+\s*=\s*\S+\s+)*([A-Za-z_][A-Za-z0-9_]*)((?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)/gi)) {
    add(match[1]);
    for (const also of match[2]?.split(",") ?? []) add(also.trim());
  }
  for (const match of query.matchAll(/\bjoin\s+(?:[\w.]+\s*=\s*\S+\s+)*\(\s*([A-Za-z_][A-Za-z0-9_]*)/gi)) {
    add(match[1]);
  }
  return [...found.values()];
}

/**
 * Caches the tenant's columns for tables a query just read.
 *
 * This is what makes the cache useful in an ordinary investigation, where the model asks a
 * question and gets a query rather than starting with a schema lookup. Probes run one at a time,
 * since each rewrites the whole cache file, and a table whose columns are still inside the TTL
 * costs nothing at all.
 *
 * Failures are swallowed on purpose. The rows the user asked for already came back, and the
 * schema tool probes again on demand.
 */
export async function warmTables(
  auth: Authenticator,
  config: Config,
  tables: string[],
  options: { env?: NodeJS.ProcessEnv } = {},
): Promise<void> {
  for (const table of tables) {
    await liveColumns(auth, config, table, options).catch(() => undefined);
  }
}

/** Drops every cached tenant column, so signing out leaves no tenant metadata behind. */
export async function clearLiveCache(env: NodeJS.ProcessEnv = process.env): Promise<boolean> {
  try {
    await rm(liveCachePath(env));
    return true;
  } catch {
    return false;
  }
}
