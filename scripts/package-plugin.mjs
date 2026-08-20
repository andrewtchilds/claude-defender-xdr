#!/usr/bin/env node
/**
 * Builds the distributable Claude plugin ZIP.
 *
 * Stages the files the installed plugin actually needs into `<out-dir>/defender-xdr`, then zips
 * that directory so the archive holds a single top-level folder. Claude Code accepts either that
 * layout or the plugin contents at the archive root:
 * https://code.claude.com/docs/en/plugin-marketplaces#zip-archives
 *
 * Usage:
 *   node scripts/package-plugin.mjs                 build build/defender-xdr-v<version>.zip
 *   node scripts/package-plugin.mjs --tag v1.2.2    also require the tag to match the manifest
 *   node scripts/package-plugin.mjs --out-dir tmp   stage and zip somewhere other than build/
 *
 * With GITHUB_OUTPUT set, the version, staging path, zip path, and digest are appended to it for
 * the release workflow to consume, so no path or version is spelled out twice.
 */

import { createHash } from "node:crypto";
import {
  appendFileSync,
  cpSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { deflateRawSync } from "node:zlib";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PLUGIN_NAME = "defender-xdr";

/**
 * Everything the installed plugin needs, and nothing else. Paths are relative to the repository
 * root; a trailing slash means "copy the directory whole".
 *
 * Deliberately absent:
 *   schema-snapshot/  esbuild inlines the JSON into dist/server.js, so it is a build input only
 *   src/ test/ scripts/ docs/ tsconfig.json vitest.config.ts   build and development material
 *   .claude-plugin/marketplace.json   describes the repository as a marketplace, not the plugin
 *   package-lock.json  the plugin runs from the bundle with no node_modules present
 */
export const INCLUDE = [
  ".claude-plugin/plugin.json",
  "skills/",
  "dist/",
  "README.md",
  "LICENSE",
  "SECURITY.md",
];

/**
 * The staged package.json exists for one reason: dist/server.js is ESM with a .js extension, so
 * Node decides its module type from the nearest package.json. Without "type": "module" the plugin
 * fails to start on Node versions that predate module detection. It is generated rather than
 * copied so no devDependencies or scripts travel with the plugin, and so the version has a single
 * source of truth in .claude-plugin/plugin.json.
 */
export function runtimePackageJson(version) {
  return `${JSON.stringify(
    {
      name: "claude-defender-xdr",
      version,
      private: true,
      type: "module",
    },
    null,
    2,
  )}\n`;
}

export function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/** Strips the leading `v` from a release tag, rejecting anything that is not `vX.Y.Z`. */
export function versionFromTag(tag) {
  const match = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.exec(tag);
  if (!match) {
    throw new Error(`Tag "${tag}" is not a version tag. Expected something like v1.2.2.`);
  }
  return match[1];
}

/** Fails loudly when the tag and the manifest disagree, naming both so the fix is obvious. */
export function assertTagMatchesVersion(tag, manifestVersion) {
  const tagVersion = versionFromTag(tag);
  if (tagVersion !== manifestVersion) {
    throw new Error(
      `Tag ${tag} does not match .claude-plugin/plugin.json version ${manifestVersion}. ` +
        `Bump the manifest to ${tagVersion}, or retag as v${manifestVersion}.`,
    );
  }
  return tagVersion;
}

/** The repository already carries the version twice; keep the two copies honest. */
export function assertManifestMatchesPackage(manifestVersion, packageVersion) {
  if (manifestVersion !== packageVersion) {
    throw new Error(
      `.claude-plugin/plugin.json version ${manifestVersion} does not match package.json ` +
        `version ${packageVersion}. Set both to the version you are releasing.`,
    );
  }
}

function walk(dir, prefix, out) {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.dirs.push(`${rel}/`);
      walk(join(dir, entry.name), rel, out);
    } else if (entry.isFile()) {
      out.files.push(rel);
    }
  }
  return out;
}

/** Lists a staged tree as sorted, forward-slash paths relative to its root. */
export function listTree(root) {
  return walk(root, "", { files: [], dirs: [] });
}

/** Copies the allowlist into a fresh staging directory and adds the generated package.json. */
export function stage({ root, outDir, version }) {
  const stagingDir = join(outDir, PLUGIN_NAME);
  rmSync(stagingDir, { recursive: true, force: true });
  mkdirSync(stagingDir, { recursive: true });

  for (const item of INCLUDE) {
    const source = join(root, item.replace(/\/$/, ""));
    if (!statSync(source, { throwIfNoEntry: false })) {
      throw new Error(`${item} is in the package allowlist but missing from the repository.`);
    }
    const target = join(stagingDir, item.replace(/\/$/, ""));
    mkdirSync(dirname(target), { recursive: true });
    cpSync(source, target, { recursive: true });
  }

  writeFileSync(join(stagingDir, "package.json"), runtimePackageJson(version));
  return { stagingDir, ...listTree(stagingDir) };
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// A fixed 2020-01-01 timestamp, so the same input always produces a byte-identical archive and a
// release can be reproduced and compared by digest.
const DOS_TIME = 0;
const DOS_DATE = ((2020 - 1980) << 9) | (1 << 5) | 1;

/**
 * Writes a ZIP from `entries` ({ path, data }, directories being paths that end in `/`). Hand-rolled
 * against the ZIP spec because the plugin has no build-time archive dependency and `zip` is not
 * present on every platform this repository supports.
 */
export function createZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const entry of entries) {
    const isDir = entry.path.endsWith("/");
    const name = Buffer.from(entry.path, "utf8");
    const raw = isDir ? Buffer.alloc(0) : Buffer.from(entry.data);
    const deflated = isDir ? Buffer.alloc(0) : deflateRawSync(raw, { level: 9 });
    // Store rather than deflate when compression does not pay, which keeps tiny files honest.
    const stored = !isDir && deflated.length >= raw.length;
    const body = isDir || stored ? raw : deflated;
    const method = isDir || stored ? 0 : 8;
    const crc = crc32(raw);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x031e, 4); // made by UNIX, zip 3.0
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(isDir ? 0x41ed0010 : 0x81a40000, 38); // 0755 dir / 0644 file
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);

    offset += local.length + name.length + body.length;
  }

  const centralBuf = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...locals, centralBuf, end]);
}

/** Stages, zips, and returns everything the caller needs to publish the release. */
export function packagePlugin({ root, outDir, tag }) {
  const manifest = readJson(join(root, ".claude-plugin", "plugin.json"));
  const version = manifest.version;
  if (!version) throw new Error(".claude-plugin/plugin.json has no version field.");
  assertManifestMatchesPackage(version, readJson(join(root, "package.json")).version);
  if (tag) assertTagMatchesVersion(tag, version);

  const { stagingDir, files, dirs } = stage({ root, outDir, version });

  const entries = [
    { path: `${PLUGIN_NAME}/` },
    ...dirs.map(dir => ({ path: `${PLUGIN_NAME}/${dir}` })),
    ...files.map(file => ({
      path: `${PLUGIN_NAME}/${file}`,
      data: readFileSync(join(stagingDir, file)),
    })),
  ].sort((a, b) => (a.path < b.path ? -1 : 1));

  const zip = createZip(entries);
  const zipPath = join(outDir, `${PLUGIN_NAME}-v${version}.zip`);
  writeFileSync(zipPath, zip);

  return {
    version,
    stagingDir,
    zipPath,
    files,
    bytes: zip.length,
    sha256: createHash("sha256").update(zip).digest("hex"),
  };
}

function parseArgs(argv) {
  const options = { outDir: "build", tag: undefined };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--tag") options.tag = argv[++i];
    else if (argv[i] === "--out-dir") options.outDir = argv[++i];
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  return options;
}

function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const { outDir, tag } = parseArgs(process.argv.slice(2));
  const absoluteOutDir = resolve(root, outDir);
  mkdirSync(absoluteOutDir, { recursive: true });

  const result = packagePlugin({ root, outDir: absoluteOutDir, tag });

  for (const file of result.files) console.log(`  ${PLUGIN_NAME}/${file}`);
  console.log(
    `\n${basename(result.zipPath)}  ${result.files.length} files, ` +
      `${(result.bytes / 1024).toFixed(0)} KiB\nsha256  ${result.sha256}`,
  );

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `version=${result.version}\nzip=${result.zipPath}\nstaging=${result.stagingDir}\n` +
        `sha256=${result.sha256}\n`,
    );
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    main();
  } catch (error) {
    console.error(`package-plugin: ${error.message}`);
    process.exit(1);
  }
}
