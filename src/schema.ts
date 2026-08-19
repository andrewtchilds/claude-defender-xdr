// The snapshot is imported, not read from disk, so it is embedded in the bundle. That
// removes any dependence on the plugin's install path at runtime.
import snapshot from "../schema-snapshot/defender-xdr-schema.json" with { type: "json" };

export interface SchemaColumn {
  name: string;
  type: string;
  description: string;
}

export interface SchemaTable {
  name: string;
  description: string;
  status: "active" | "preview" | "retired";
  replacedBy?: string;
  retirementDate?: string;
  documentationUrl: string;
  columns: SchemaColumn[];
}

interface Snapshot {
  sourceDate: string | null;
  sourceUrl: string;
  tables: SchemaTable[];
}

const SEARCH_LIMIT = 20;

export const schema = snapshot as unknown as Snapshot;

export function findTable(name: string): SchemaTable | undefined {
  const wanted = name.trim().toLowerCase();
  return schema.tables.find(table => table.name.toLowerCase() === wanted);
}

export function listTables(includeRetired: boolean) {
  return schema.tables
    .filter(table => includeRetired || table.status !== "retired")
    .map(({ name, description, status, replacedBy }) => ({
      name,
      description,
      status,
      ...(replacedBy ? { replacedBy } : {}),
    }));
}

/**
 * Matches every whitespace-separated term independently, so a natural-language phrase
 * such as "process command line" still finds the `ProcessCommandLine` column that a
 * single substring match would miss.
 */
export function searchTables(term: string, includeRetired: boolean, limit = SEARCH_LIMIT) {
  const terms = term.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [];
  const matchesAll = (haystack: string) => terms.every(needle => haystack.includes(needle));
  const columnMatches = (column: SchemaColumn) =>
    matchesAll(`${column.name} ${column.description}`.toLowerCase());

  return schema.tables
    .filter(table => includeRetired || table.status !== "retired")
    .map(table => ({ table, columns: table.columns.filter(columnMatches) }))
    .filter(
      ({ table, columns }) =>
        columns.length > 0 || matchesAll(`${table.name} ${table.description}`.toLowerCase()),
    )
    // Tables with concrete column hits are more useful than a description-only match.
    .sort((a, b) => b.columns.length - a.columns.length)
    .slice(0, limit)
    .map(({ table, columns }) => ({
      table: table.name,
      description: table.description,
      status: table.status,
      matchingColumns: columns.slice(0, SEARCH_LIMIT),
    }));
}

/** Ranks by name similarity so an unknown table still produces a useful suggestion. */
export function suggestTables(name: string, limit = 5): string[] {
  const needle = name.trim().toLowerCase();
  return schema.tables
    .filter(table => table.status !== "retired")
    .map(table => {
      const candidate = table.name.toLowerCase();
      const score = candidate.includes(needle) || needle.includes(candidate) ? 0 : 1;
      return { name: table.name, score };
    })
    .sort((a, b) => a.score - b.score)
    .slice(0, limit)
    .map(entry => entry.name);
}
