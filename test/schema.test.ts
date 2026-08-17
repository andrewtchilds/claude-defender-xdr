import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { findSchemaTable, loadSchemaSnapshot, searchSchema } from "../server/schema.js";

const SKILLS_DIR = "skills";

describe("bundled schema snapshot", () => {
  it("loads and exposes provenance", async () => {
    const snapshot = await loadSchemaSnapshot();
    expect(snapshot.tables.length).toBeGreaterThan(50);
    expect(snapshot.sourceCommit).toMatch(/^[0-9a-f]{40}$/);
    expect(snapshot.sourceUrl).toMatch(/^https:\/\//);
  });

  it("has unique, well-formed tables", async () => {
    const { tables } = await loadSchemaSnapshot();
    expect(new Set(tables.map(t => t.name)).size).toBe(tables.length);
    for (const table of tables) {
      expect(["active", "preview", "retired"], table.name).toContain(table.status);
      expect(table.columns.length, table.name).toBeGreaterThan(0);
    }
  });

  it("resolves table lookups case-insensitively", async () => {
    expect((await findSchemaTable("  deviceinfo "))?.name).toBe("DeviceInfo");
    expect(await findSchemaTable("NoSuchTable")).toBeUndefined();
  });

  it("searches names, descriptions, and columns, hiding retired tables by default", async () => {
    const snapshot = await loadSchemaSnapshot();
    expect(searchSchema(snapshot, "NetworkMessageId").map(m => m.table)).toContain("EmailEvents");
    expect(searchSchema(snapshot, "   ")).toEqual([]);
    expect(searchSchema(snapshot, "sign-in").every(m => m.status !== "retired")).toBe(true);
    expect(searchSchema(snapshot, "x", true, 3).length).toBeLessThanOrEqual(3);
  });
});

/**
 * The skills tell Claude which tables to query. If Microsoft retires one and the snapshot
 * is refreshed without updating the skills, the plugin starts recommending dead tables.
 */
describe("skill query patterns", () => {
  const markdown = readdirSync(SKILLS_DIR, { withFileTypes: true })
    .filter(entry => entry.isDirectory())
    .flatMap(entry => [
      join(SKILLS_DIR, entry.name, "SKILL.md"),
      join(SKILLS_DIR, entry.name, "references", "query-patterns.md"),
    ])
    .filter(path => {
      try {
        readFileSync(path);
        return true;
      } catch {
        return false;
      }
    });

  it("finds skill documentation to check", () => {
    expect(markdown.length).toBeGreaterThan(0);
  });

  it("only reference tables that exist and are not retired", async () => {
    const snapshot = await loadSchemaSnapshot();
    const known = new Map(snapshot.tables.map(t => [t.name, t]));
    const problems: string[] = [];

    for (const path of markdown) {
      const text = readFileSync(path, "utf8");
      for (const block of text.matchAll(/```kusto\n([\s\S]*?)```/g)) {
        // A source table is an identifier on its own line, immediately followed by a pipe.
        for (const match of block[1]!.matchAll(/(?:^|\n)[ \t]*([A-Z][A-Za-z0-9]{4,})[ \t]*(?=\n[ \t]*\|)/g)) {
          const name = match[1]!;
          const table = known.get(name);
          if (!table) continue; // Not a table reference (e.g. a projected column before a pipe).
          if (table.status === "retired") problems.push(`${path}: ${name} is retired`);
        }
      }
    }

    expect(problems).toEqual([]);
  });
});
