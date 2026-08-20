// Written as .mjs so the packaging script, which is plain Node rather than TypeScript, can be
// imported without turning on allowJs for the whole project.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
import { afterAll, describe, expect, it } from "vitest";

import {
  INCLUDE,
  PLUGIN_NAME,
  assertManifestMatchesPackage,
  assertTagMatchesVersion,
  createZip,
  packagePlugin,
  versionFromTag,
} from "../scripts/package-plugin.mjs";

const root = resolve(import.meta.dirname, "..");
const outDir = mkdtempSync(join(tmpdir(), "defender-xdr-package-"));
const built = packagePlugin({ root, outDir });

afterAll(() => rmSync(outDir, { recursive: true, force: true }));

/** Reads back the entry names and file bodies from a ZIP's central directory. */
function readZip(buffer) {
  const endOffset = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = buffer.readUInt16LE(endOffset + 10);
  let cursor = buffer.readUInt32LE(endOffset + 16);
  const entries = [];
  for (let i = 0; i < count; i++) {
    expect(buffer.readUInt32LE(cursor)).toBe(0x02014b50);
    const method = buffer.readUInt16LE(cursor + 10);
    const compressed = buffer.readUInt32LE(cursor + 20);
    const uncompressed = buffer.readUInt32LE(cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const localOffset = buffer.readUInt32LE(cursor + 42);
    const path = buffer.toString("utf8", cursor + 46, cursor + 46 + nameLength);

    const bodyStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26);
    const body = buffer.subarray(bodyStart, bodyStart + compressed);
    entries.push({
      path,
      data: path.endsWith("/") ? Buffer.alloc(0) : method === 8 ? inflateRawSync(body) : body,
      uncompressed,
    });
    cursor += 46 + nameLength;
  }
  return entries;
}

describe("version checks", () => {
  it("accepts a version tag and strips the v", () => {
    expect(versionFromTag("v1.2.2")).toBe("1.2.2");
    expect(versionFromTag("v1.2.2-rc.1")).toBe("1.2.2-rc.1");
  });

  it("rejects anything that is not a version tag", () => {
    for (const tag of ["1.2.2", "release-1.2.2", "v1.2", "v1.2.2.3", ""]) {
      expect(() => versionFromTag(tag)).toThrow(/not a version tag/);
    }
  });

  it("names both versions when the tag and the manifest disagree", () => {
    expect(() => assertTagMatchesVersion("v1.2.2", "1.2.1")).toThrow(/v1\.2\.2.*1\.2\.1/s);
    expect(assertTagMatchesVersion("v1.2.2", "1.2.2")).toBe("1.2.2");
  });

  it("catches drift between the manifest and package.json", () => {
    expect(() => assertManifestMatchesPackage("1.2.2", "1.2.1")).toThrow(/does not match/);
  });
});

describe("zip writer", () => {
  it("round-trips file contents and directory markers", () => {
    const body = Buffer.from("hello".repeat(200));
    const entries = readZip(createZip([{ path: "a/" }, { path: "a/b.txt", data: body }]));
    expect(entries.map(entry => entry.path)).toEqual(["a/", "a/b.txt"]);
    expect(entries[1].data.toString()).toBe(body.toString());
    expect(entries[1].uncompressed).toBe(body.length);
  });

  it("stores rather than inflates content that does not compress", () => {
    const entries = readZip(createZip([{ path: "x", data: Buffer.from("q") }]));
    expect(entries[0].data.toString()).toBe("q");
  });

  it("is byte-identical for identical input", () => {
    const input = [{ path: "a/" }, { path: "a/b.txt", data: Buffer.from("same") }];
    expect(createZip(input).equals(createZip(input))).toBe(true);
  });
});

describe("packaged plugin", () => {
  const zip = readZip(readFileSync(built.zipPath));
  const paths = zip.map(entry => entry.path);

  it("nests everything under a single top-level plugin directory", () => {
    expect(built.zipPath.endsWith(`${PLUGIN_NAME}-v${built.version}.zip`)).toBe(true);
    expect(paths.every(path => path.startsWith(`${PLUGIN_NAME}/`))).toBe(true);
    expect(new Set(paths.map(path => path.split("/")[0])).size).toBe(1);
  });

  it("carries the manifest, the bundle, and the skills", () => {
    expect(paths).toContain(`${PLUGIN_NAME}/.claude-plugin/plugin.json`);
    expect(paths).toContain(`${PLUGIN_NAME}/dist/server.js`);
    expect(paths).toContain(`${PLUGIN_NAME}/skills/xdr-login/SKILL.md`);
    expect(paths.filter(path => path.endsWith("/SKILL.md")).length).toBeGreaterThanOrEqual(4);
    for (const item of INCLUDE) {
      expect(paths.some(path => path.startsWith(`${PLUGIN_NAME}/${item}`))).toBe(true);
    }
  });

  it("declares ESM so Node runs the bundle, without shipping dev dependencies", () => {
    const entry = zip.find(item => item.path === `${PLUGIN_NAME}/package.json`);
    const manifest = JSON.parse(entry.data.toString());
    expect(manifest.type).toBe("module");
    expect(manifest.version).toBe(built.version);
    expect(manifest.devDependencies).toBeUndefined();
    expect(manifest.scripts).toBeUndefined();
  });

  it("leaves development material out", () => {
    for (const excluded of [
      "src/",
      "test/",
      "scripts/",
      "docs/",
      "schema-snapshot/",
      "node_modules/",
      ".github/",
      "tsconfig.json",
      "vitest.config.ts",
      "package-lock.json",
      ".claude-plugin/marketplace.json",
      "commands/",
    ]) {
      expect(paths.some(path => path.startsWith(`${PLUGIN_NAME}/${excluded}`))).toBe(false);
    }
  });

  it("stays well inside the 50 MB organization upload limit", () => {
    expect(built.bytes).toBeLessThan(50 * 1024 * 1024);
    expect(built.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});
