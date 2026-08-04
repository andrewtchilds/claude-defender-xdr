import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { XdrAuth } from "./auth.js";
import type { XdrConfig } from "./config.js";
import { runHuntingQuery } from "./client.js";
export interface SchemaColumn { name: string; type: string; description: string }
export interface SchemaTable { name: string; description: string; preview: boolean; status: "active" | "preview" | "retired"; replacedBy?: string; retirementDate?: string; columns: SchemaColumn[]; documentationUrl: string }
export interface SchemaSnapshot { schemaVersion: number; source: string; sourceUrl: string; sourceRepository: string; sourceCommit: string; sourceDate: string | null; schemaChangesUrl: string; tables: SchemaTable[] }
let snapshot: Promise<SchemaSnapshot> | undefined;
export function loadSchemaSnapshot() { snapshot ??= readFile(join(process.env.CLAUDE_PLUGIN_ROOT ?? process.cwd(), "schema-snapshot", "defender-xdr-schema.json"), "utf8").then(x => validate(JSON.parse(x))); return snapshot; }
export async function findSchemaTable(name: string) { return (await loadSchemaSnapshot()).tables.find(t => t.name.toLowerCase() === name.trim().toLowerCase()); }
export function searchSchema(s: SchemaSnapshot, term: string, retired = false, limit = 20) { const n = term.trim().toLowerCase(); if (!n) return []; return s.tables.filter(t => (retired || t.status !== "retired") && (`${t.name} ${t.description}`.toLowerCase().includes(n) || t.columns.some(c => `${c.name} ${c.description}`.toLowerCase().includes(n)))).slice(0, limit).map(t => ({ table: t.name, tableDescription: t.description, status: t.status, matchingColumns: t.columns.filter(c => `${c.name} ${c.description}`.toLowerCase().includes(n)).slice(0, 20) })); }
export async function liveColumns(table: SchemaTable, auth: XdrAuth, config: XdrConfig, signal?: AbortSignal) { const r = await runHuntingQuery(auth, config, { query: `${table.name}\n| take 0`, timespan: config.defaultLookback }, signal); return { columns: r.schema, fetchedAt: new Date().toISOString() }; }
function validate(v: unknown): SchemaSnapshot { if (!v || typeof v !== "object" || !Array.isArray((v as { tables?: unknown }).tables)) throw new Error("Bundled Defender XDR schema snapshot is invalid"); return v as SchemaSnapshot; }
