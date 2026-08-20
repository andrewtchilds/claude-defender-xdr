import { mkdir, mkdtemp, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Authenticator } from "../src/auth.js";
import type { Config } from "../src/config.js";
import {
  clearLiveCache,
  liveCachePath,
  liveColumns,
  mergeColumns,
  searchLiveCache,
  UNDOCUMENTED,
} from "../src/live-schema.js";

afterEach(() => vi.unstubAllGlobals());

const config = (tenantId = "11111111-1111-1111-1111-111111111111"): Config => ({
  tenantId,
  clientId: "22222222-2222-2222-2222-222222222222",
  graphBaseUrl: "https://graph.microsoft.com",
  loginBaseUrl: "https://login.microsoftonline.com",
  maxRows: 1000,
  defaultTimespan: "7d",
});

/** Stands in for a signed-in user without touching the token file or the network. */
const signedIn = { accessTokenSilent: async () => "token" } as unknown as Authenticator;

/** `XDG_CONFIG_HOME` is honoured on every platform, so one env override redirects all state. */
async function isolatedEnv(): Promise<NodeJS.ProcessEnv> {
  return { XDG_CONFIG_HOME: await mkdtemp(join(tmpdir(), "xdr-schema-")) };
}

function stubGraph(columns: { name: string; type?: string }[]) {
  const fetchMock = vi.fn(
    async (_url: string, _init: RequestInit = {}) =>
      new Response(JSON.stringify({ schema: columns, results: [] }), { status: 200 }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function seedCache(env: NodeJS.ProcessEnv, cache: unknown): Promise<string> {
  const path = liveCachePath(env);
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, JSON.stringify(cache));
  return path;
}

describe("live tenant schema", () => {
  it("asks the tenant once, then serves the same columns from disk", async () => {
    const env = await isolatedEnv();
    const fetchMock = stubGraph([{ name: "DeviceId", type: "String" }]);

    const first = await liveColumns(signedIn, config(), "DeviceInfo", { env });
    const second = await liveColumns(signedIn, config(), "DeviceInfo", { env });

    expect(first).toMatchObject({ cached: false, columns: [{ name: "DeviceId", type: "String" }] });
    expect(second).toMatchObject({ cached: true, columns: [{ name: "DeviceId", type: "String" }] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("asks for the whole table and no rows at all", async () => {
    const env = await isolatedEnv();
    const fetchMock = stubGraph([{ name: "DeviceId" }]);

    await liveColumns(signedIn, config(), "DeviceInfo", { env });

    const body = JSON.parse(fetchMock.mock.calls[0]![1]!.body as string) as Record<string, string>;
    expect(body.Query).toBe("DeviceInfo\n| take 0");
    expect(body.Timespan).toBe("P7D");
  });

  it("refetches when the cached entry is older than the TTL", async () => {
    const env = await isolatedEnv();
    await seedCache(env, {
      version: 1,
      tenantId: config().tenantId,
      tables: {
        deviceinfo: { name: "DeviceInfo", fetchedAt: "2026-01-01T00:00:00.000Z", columns: [{ name: "Stale" }] },
      },
    });
    const fetchMock = stubGraph([{ name: "Fresh" }]);

    const result = await liveColumns(signedIn, config(), "DeviceInfo", { env });

    expect(result).toMatchObject({ cached: false, columns: [{ name: "Fresh" }] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refetches on refresh even when the cache is fresh", async () => {
    const env = await isolatedEnv();
    const fetchMock = stubGraph([{ name: "DeviceId" }]);

    await liveColumns(signedIn, config(), "DeviceInfo", { env });
    const refreshed = await liveColumns(signedIn, config(), "DeviceInfo", { env, refresh: true });

    expect(refreshed.cached).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("ignores a cache written for another tenant instead of serving its columns", async () => {
    const env = await isolatedEnv();
    await seedCache(env, {
      version: 1,
      tenantId: "99999999-9999-9999-9999-999999999999",
      tables: {
        deviceinfo: { name: "DeviceInfo", fetchedAt: new Date().toISOString(), columns: [{ name: "OtherTenant" }] },
      },
    });
    const fetchMock = stubGraph([{ name: "DeviceId" }]);

    const result = await liveColumns(signedIn, config(), "DeviceInfo", { env });

    expect(result.columns).toEqual([{ name: "DeviceId" }]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await expect(searchLiveCache("OtherTenant", config().tenantId, env)).resolves.toEqual([]);
  });

  it("rebuilds a damaged cache rather than failing the lookup", async () => {
    const env = await isolatedEnv();
    await seedCache(env, "not a cache");
    stubGraph([{ name: "DeviceId" }]);

    await expect(liveColumns(signedIn, config(), "DeviceInfo", { env })).resolves.toMatchObject({
      cached: false,
    });
  });

  it("keeps the cache readable only by its owner", async () => {
    if (process.platform === "win32") return;
    const env = await isolatedEnv();
    stubGraph([{ name: "DeviceId" }]);

    await liveColumns(signedIn, config(), "DeviceInfo", { env });

    expect((await stat(liveCachePath(env))).mode & 0o777).toBe(0o600);
  });

  // The table name is interpolated into KQL, so the guard has to come before the query.
  it("refuses a table name that is not a bare identifier, without querying", async () => {
    const env = await isolatedEnv();
    const fetchMock = stubGraph([{ name: "DeviceId" }]);

    for (const name of ["DeviceInfo | where 1==1", "Device-Info", "", "1Device", "Device;drop"]) {
      await expect(liveColumns(signedIn, config(), name, { env })).rejects.toThrow(/not a Defender XDR table name/);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("finds cached tenant columns the documentation does not have, with no query", async () => {
    const env = await isolatedEnv();
    await seedCache(env, {
      version: 1,
      tenantId: config().tenantId,
      tables: {
        entraidsigninevents: {
          name: "EntraIdSignInEvents",
          fetchedAt: "2026-07-13T21:43:45.140Z",
          columns: [{ name: "RiskLevelDuringSignIn", type: "Int32" }, { name: "Timestamp", type: "DateTime" }],
        },
      },
    });
    const fetchMock = stubGraph([]);

    await expect(searchLiveCache("risk level", config().tenantId, env)).resolves.toEqual([
      {
        table: "EntraIdSignInEvents",
        fetchedAt: "2026-07-13T21:43:45.140Z",
        matchingColumns: [{ name: "RiskLevelDuringSignIn", type: "Int32" }],
      },
    ]);
    expect(await searchLiveCache("   ", config().tenantId, env)).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("deletes the cache on demand, and says whether there was one", async () => {
    const env = await isolatedEnv();
    stubGraph([{ name: "DeviceId" }]);
    await liveColumns(signedIn, config(), "DeviceInfo", { env });

    await expect(clearLiveCache(env)).resolves.toBe(true);
    await expect(clearLiveCache(env)).resolves.toBe(false);
  });
});

describe("mergeColumns", () => {
  const documented = [
    { name: "DeviceId", type: "string", description: "Unique identifier for the device" },
    { name: "RetiredColumn", type: "string", description: "Documented but gone" },
  ];

  it("takes the column list from the tenant and the prose from the documentation", () => {
    const merged = mergeColumns(documented, [{ name: "DeviceId", type: "String" }, { name: "BrandNew", type: "String" }]);

    expect(merged.columns).toEqual([
      { name: "DeviceId", type: "String", description: "Unique identifier for the device" },
      { name: "BrandNew", type: "String", description: UNDOCUMENTED },
    ]);
    expect(merged.documentedOnly).toEqual(["RetiredColumn"]);
  });

  it("matches names case-insensitively, and keeps the tenant's spelling", () => {
    const merged = mergeColumns(documented, [{ name: "deviceid", type: "String" }]);

    expect(merged.columns[0]).toEqual({
      name: "deviceid",
      type: "String",
      description: "Unique identifier for the device",
    });
  });

  it("falls back to the documented type when the tenant does not report one", () => {
    expect(mergeColumns(documented, [{ name: "DeviceId" }]).columns[0]!.type).toBe("string");
    expect(mergeColumns([], [{ name: "Mystery" }]).columns[0]!.type).toBe("unknown");
  });
});
