#!/usr/bin/env node
/**
 * Rebuilds `schema-snapshot/defender-xdr-schema.json` from Microsoft's own documentation.
 *
 * The snapshot is what `xdr_get_schema` answers from offline, and the only source that can say
 * what a column *means* — the tenant itself reports names and types and nothing else. It is
 * generated rather than hand-maintained, and pinned to the documentation commit it was built
 * from, so a regeneration is reviewable: the diff shows exactly what Microsoft changed.
 *
 * Usage:
 *   node scripts/update-schema-snapshot.mjs           rebuild the snapshot in place
 *   node scripts/update-schema-snapshot.mjs --check    report drift, write nothing, exit 1
 *
 * Set GITHUB_TOKEN to raise the anonymous GitHub API rate limit if you run this repeatedly.
 */
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Microsoft publishes the Defender documentation here, and edits land on `public`. */
const REPOSITORY = "MicrosoftDocs/defender-docs";
const BRANCH = "public";
const DOCS_PATH = "defender-xdr";
const INDEX_DOCUMENT = "advanced-hunting-schema-tables.md";

const LEARN_BASE = "https://learn.microsoft.com/en-us/defender-xdr";
const SCHEMA_CHANGES_URL = `${LEARN_BASE}/advanced-hunting-schema-changes`;

/** Fetch this many table documents at once: polite to raw.githubusercontent, still quick. */
const CONCURRENCY = 8;
const MAX_ATTEMPTS = 3;

/**
 * Retirements Microsoft announces in prose rather than in the schema tables, so they cannot be
 * parsed out of the index. Curated by hand against the schema-changes page, and checked below
 * against what the documentation actually lists so an entry cannot rot unnoticed.
 *
 * @see https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-changes
 */
const RETIREMENTS = {
  AADSignInEventsBeta: { replacedBy: "EntraIdSignInEvents", retirementDate: "2025-12-09" },
  AADSpnSignInEventsBeta: { replacedBy: "EntraIdSpnSignInEvents", retirementDate: "2025-12-09" },
  AIAgentsInfo: { replacedBy: "AgentsInfo", retirementDate: "2026-07-01" },
};

const snapshotPath = resolve(dirname(fileURLToPath(import.meta.url)), "../schema-snapshot/defender-xdr-schema.json");
const checkOnly = process.argv.includes("--check");

/**
 * Fetches one document, retrying the failures that are worth retrying.
 *
 * Around 65 documents are pulled in a burst, so an occasional 429 or 5xx from GitHub is normal
 * and means "wait", not "give up" — while a 404 means the index points at a document that no
 * longer exists, which is a real problem to report rather than paper over.
 */
async function fetchText(url) {
  const headers = { "user-agent": "claude-defender-xdr-schema-generator" };
  if (process.env.GITHUB_TOKEN && url.startsWith("https://api.github.com/")) {
    headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  for (let attempt = 1; ; attempt++) {
    const response = await fetch(url, { headers });
    if (response.ok) return await response.text();
    const retryable = response.status === 429 || response.status >= 500;
    if (!retryable || attempt === MAX_ATTEMPTS) {
      throw new Error(`Unable to fetch ${url}: HTTP ${response.status}`);
    }
    const waitMs = Number(response.headers.get("retry-after")) * 1000 || 1000 * 2 ** attempt;
    console.warn(`  HTTP ${response.status} on ${url}; retrying in ${Math.round(waitMs / 1000)}s`);
    await new Promise(done => setTimeout(done, waitMs));
  }
}

/** Runs `mapper` over every value with a fixed number of workers, preserving input order. */
async function mapConcurrent(values, concurrency, mapper) {
  const output = new Array(values.length);
  let next = 0;
  const worker = async () => {
    while (next < values.length) {
      const index = next++;
      output[index] = await mapper(values[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, worker));
  return output;
}

/** Reduces documentation markup to the plain prose a tool result should carry. */
function cleanMarkdown(value) {
  return String(value ?? "")
    .replace(/\[([^\]]+)]\([^)]+\)/g, "$1")
    .replace(/[`*_]/g, "")
    .replace(/<br\s*\/?\s*>/gi, " ")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/\\\|/g, "|")
    .replace(/\s+/g, " ")
    .trim();
}

/** Splits one markdown table row, respecting the `\|` a description may contain. */
function splitRow(line) {
  const cells = [];
  let current = "";
  let escaped = false;
  for (const character of line.trim().replace(/^\|/, "").replace(/\|$/, "")) {
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
      current += character;
    } else if (character === "|") {
      cells.push(current.trim());
      current = "";
    } else {
      current += character;
    }
  }
  cells.push(current.trim());
  return cells;
}

/**
 * Pulls the column list out of one table's document.
 *
 * Every page carries the same three-column table, though the first heading is sometimes
 * "Column name" and sometimes "Column", and a description can itself contain a pipe.
 */
function parseColumns(markdown) {
  const lines = markdown.split(/\r?\n/);
  const header = lines.findIndex(line => /^\|\s*(?:Column name|Column)\s*\|\s*Data type\s*\|\s*Description\s*\|/i.test(line));
  if (header < 0) return [];

  const columns = [];
  // Skip the header and the `|---|` separator beneath it, then read until the table ends.
  for (let index = header + 2; index < lines.length && /^\s*\|/.test(lines[index]); index++) {
    const cells = splitRow(lines[index]);
    if (cells.length < 3) continue;
    const name = cleanMarkdown(cells[0]);
    if (name) {
      columns.push({ name, type: cleanMarkdown(cells[1]), description: cleanMarkdown(cells.slice(2).join(" | ")) });
    }
  }
  return columns;
}

/** Names every table in the index, with the document that describes it. */
function parseIndex(markdown) {
  const pattern = /^\|\s*\*\*\[([^\]]+)]\((advanced-hunting-[^)]+-table\.md)\)\*\*\s*(\(Preview\))?\s*\|\s*(.*?)\s*\|\s*$/gm;
  const entries = [];
  for (const match of markdown.matchAll(pattern)) {
    entries.push({
      name: match[1],
      document: match[2].toLowerCase(),
      preview: Boolean(match[3]),
      description: cleanMarkdown(match[4]),
    });
  }
  return entries;
}

/** Reports what a regeneration would change, so the JSON diff is not the only account of it. */
function summarize(previous, next) {
  if (!previous) {
    console.log("No previous snapshot; everything is new.");
    return true;
  }

  const changes = [];
  if (previous.sourceCommit !== next.sourceCommit) {
    changes.push(`documentation commit ${previous.sourceCommit.slice(0, 8)} → ${next.sourceCommit.slice(0, 8)}`);
  }
  if (previous.sourceDate !== next.sourceDate) changes.push(`documented date ${previous.sourceDate} → ${next.sourceDate}`);

  const before = new Map(previous.tables.map(table => [table.name, table]));
  const after = new Map(next.tables.map(table => [table.name, table]));
  const added = [...after.keys()].filter(name => !before.has(name));
  const removed = [...before.keys()].filter(name => !after.has(name));
  if (added.length) changes.push(`tables added: ${added.join(", ")}`);
  if (removed.length) changes.push(`tables removed: ${removed.join(", ")}`);

  for (const [name, table] of after) {
    const old = before.get(name);
    if (!old) continue;
    const oldColumns = new Set(old.columns.map(column => column.name));
    const newColumns = new Set(table.columns.map(column => column.name));
    const gained = [...newColumns].filter(column => !oldColumns.has(column));
    const lost = [...oldColumns].filter(column => !newColumns.has(column));
    if (gained.length) changes.push(`${name}: +${gained.join(", +")}`);
    if (lost.length) changes.push(`${name}: -${lost.join(", -")}`);
    if (old.status !== table.status) changes.push(`${name}: ${old.status} → ${table.status}`);
  }

  if (changes.length === 0) {
    console.log("The snapshot already matches the documentation.");
    return false;
  }
  console.log(`${changes.length} change${changes.length === 1 ? "" : "s"} since the committed snapshot:`);
  for (const change of changes) console.log(`  ${change}`);
  return true;
}

const commits = JSON.parse(
  await fetchText(`https://api.github.com/repos/${REPOSITORY}/commits?sha=${BRANCH}&path=${DOCS_PATH}/${INDEX_DOCUMENT}&per_page=1`),
);
// Pinning to a commit, rather than to the branch, is what makes the snapshot reproducible: the
// same commit fetched again yields the same tables and columns, whatever `public` does next.
const commit = commits[0]?.sha;
if (!commit) throw new Error("Unable to resolve the documentation commit for the schema index");

const rawBase = `https://raw.githubusercontent.com/${REPOSITORY}/${commit}/${DOCS_PATH}`;
const indexMarkdown = await fetchText(`${rawBase}/${INDEX_DOCUMENT}`);
const entries = parseIndex(indexMarkdown);
if (entries.length === 0) {
  throw new Error(`No tables found in ${INDEX_DOCUMENT}; the documentation layout has changed and the parser needs updating`);
}
console.log(`Reading ${entries.length} tables from ${REPOSITORY}@${commit.slice(0, 8)}`);

const tables = await mapConcurrent(entries, CONCURRENCY, async entry => {
  const columns = parseColumns(await fetchText(`${rawBase}/${entry.document}`));
  if (columns.length === 0) throw new Error(`No columns found for ${entry.name} in ${entry.document}`);
  return {
    name: entry.name,
    description: entry.description,
    preview: entry.preview,
    columns,
    documentationUrl: `${LEARN_BASE}/${entry.document.replace(/\.md$/, "")}`,
  };
});

tables.sort((a, b) => a.name.localeCompare(b.name));
const documented = new Set(tables.map(table => table.name));
for (const [name, retirement] of Object.entries(RETIREMENTS)) {
  // A retirement Microsoft has finished — the table is gone from the docs — or a replacement
  // that never arrived both mean the curated list has drifted and should be revisited.
  if (!documented.has(name)) console.warn(`  note: retired table ${name} is no longer in the documentation index`);
  if (!documented.has(retirement.replacedBy)) {
    console.warn(`  note: ${name} names ${retirement.replacedBy} as its replacement, which the documentation does not list`);
  }
}
for (const table of tables) {
  const retirement = RETIREMENTS[table.name];
  if (retirement) Object.assign(table, { status: "retired", ...retirement });
  else table.status = table.preview ? "preview" : "active";
}

const snapshot = {
  schemaVersion: 1,
  source: "Microsoft Defender XDR official documentation",
  sourceUrl: `${LEARN_BASE}/advanced-hunting-schema-tables`,
  sourceRepository: `https://github.com/${REPOSITORY}`,
  sourceCommit: commit,
  sourceDate: /^ms\.date:\s*(.+)$/m.exec(indexMarkdown)?.[1]?.trim() ?? null,
  schemaChangesUrl: SCHEMA_CHANGES_URL,
  tables,
};

const previous = await readFile(snapshotPath, "utf8").then(JSON.parse, () => undefined);
const drifted = summarize(previous, snapshot);

if (checkOnly) {
  if (drifted) {
    console.error("\nThe committed snapshot is behind the documentation. Run: npm run schema");
    process.exitCode = 1;
  }
} else {
  await writeFile(snapshotPath, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
  const columnCount = tables.reduce((total, table) => total + table.columns.length, 0);
  const statuses = tables.reduce((counts, table) => ({ ...counts, [table.status]: (counts[table.status] ?? 0) + 1 }), {});
  console.log(
    `\nWrote ${tables.length} tables (${Object.entries(statuses).map(([status, count]) => `${count} ${status}`).join(", ")}) ` +
      `and ${columnCount} columns to ${snapshotPath}`,
  );
  console.log("Rebuild and commit dist/ as well if src/ changed: npm run verify");
}
