import { describe, expect, it } from "vitest";
import { findTable, listTables, schema, searchTables, suggestTables } from "../src/schema.js";

describe("bundled schema", () => {
  it("is embedded in the module, not read from disk", () => {
    expect(schema.tables.length).toBeGreaterThan(50);
    expect(findTable("DeviceProcessEvents")?.columns.length).toBeGreaterThan(10);
  });

  // The documentation's own prose for this column describes Windows logon kinds, but tenants
  // store a JSON array string; models copying the documented wording wrote filters that
  // matched nothing. The generator carries the correction as an erratum; this guards against
  // a regeneration quietly dropping it.
  it("carries the corrected LogonType representation, not the documented prose", () => {
    const logonType = findTable("EntraIdSignInEvents")?.columns.find(column => column.name === "LogonType");
    expect(logonType?.description).toContain('["interactiveUser"]');
    expect(logonType?.description).not.toContain("(RDP)");
  });

  it("looks tables up case-insensitively", () => {
    expect(findTable("deviceprocessevents")?.name).toBe("DeviceProcessEvents");
    expect(findTable("  DeviceInfo  ")?.name).toBe("DeviceInfo");
  });

  it("hides retired tables unless asked", () => {
    const withRetired = listTables(true);
    const withoutRetired = listTables(false);
    expect(withRetired.length).toBeGreaterThan(withoutRetired.length);
    expect(withoutRetired.every(table => table.status !== "retired")).toBe(true);
  });

  // The plugin is driven by natural language, so a multi-word phrase has to match a
  // camel-case column name that contains no spaces.
  it("matches each search term independently", () => {
    const matches = searchTables("process command line", false);
    expect(matches.length).toBeGreaterThan(0);
    const columns = matches.flatMap(match => match.matchingColumns.map(column => column.name));
    expect(columns).toContain("ProcessCommandLine");
  });

  it("ranks tables with real column hits first", () => {
    const matches = searchTables("sha256", false);
    expect(matches[0]!.matchingColumns.length).toBeGreaterThan(0);
  });

  it("returns nothing for a blank search rather than everything", () => {
    expect(searchTables("   ", false)).toEqual([]);
  });

  it("suggests near misses for an unknown table", () => {
    expect(suggestTables("DeviceProcess")).toContain("DeviceProcessEvents");
  });
});
