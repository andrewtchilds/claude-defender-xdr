import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeOwnerOnlyDir, stateDir } from "../src/config.js";
import { createServer } from "../src/server.js";

const TENANT = "11111111-1111-1111-1111-111111111111";
const CLIENT = "22222222-2222-2222-2222-222222222222";

const saved = { ...process.env };

beforeEach(async () => {
  // Every path the server writes to hangs off the config directory, so one variable moves the
  // whole of it — the token, the config, and the schema cache — into a throwaway directory.
  process.env.XDG_CONFIG_HOME = await mkdtemp(join(tmpdir(), "xdr-server-"));
  process.env.XDR_TENANT_ID = TENANT;
  process.env.XDR_CLIENT_ID = CLIENT;
});

afterEach(() => {
  process.env = { ...saved };
  vi.unstubAllGlobals();
});

/** Writes the refresh token a signed-in user would already have, so silent auth succeeds. */
async function signedIn(): Promise<void> {
  const directory = stateDir();
  await makeOwnerOnlyDir(directory);
  await writeFile(
    join(directory, "token.json"),
    JSON.stringify({ refreshToken: "refresh", username: "analyst@example.com", tenantId: TENANT, clientId: CLIENT }),
  );
}

/** Answers the two endpoints the server talks to, and rejects anything else outright. */
function stubNetwork(hunting: () => Response) {
  const fetchMock = vi.fn(async (url: string, _init: RequestInit = {}) => {
    if (url.includes("/oauth2/v2.0/token")) {
      return new Response(JSON.stringify({ access_token: "access", expires_in: 3600 }), { status: 200 });
    }
    if (url.includes("/security/runHuntingQuery")) return hunting();
    throw new Error(`unexpected request to ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const tenantColumns = (columns: { name: string; type: string }[]) => () =>
  new Response(JSON.stringify({ schema: columns, results: [] }), { status: 200 });

async function connect(): Promise<(tool: string, args: Record<string, unknown>) => Promise<string>> {
  const client = new Client({ name: "test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([client.connect(clientTransport), createServer().connect(serverTransport)]);
  return async (tool, args) => {
    const result = (await client.callTool({ name: tool, arguments: args })) as { content: { text: string }[] };
    return result.content[0]!.text;
  };
}

/**
 * Waits for schema warming, which xdr_run_query starts and deliberately does not await so that
 * a query is never slowed down by it. Everything is mocked here, so this resolves in a tick or
 * two; the deadline only keeps a broken build from hanging.
 */
async function eventually(condition: () => Promise<boolean>): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (await condition()) return;
    await new Promise(done => setTimeout(done, 5));
  }
  throw new Error("condition never became true");
}

describe("xdr_get_schema against a tenant", () => {
  it("describes a documented table with the columns the tenant actually returns", async () => {
    await signedIn();
    const fetchMock = stubNetwork(
      tenantColumns([{ name: "DeviceId", type: "String" }, { name: "BrandNewColumn", type: "String" }]),
    );
    const getSchema = await connect();

    const text = await getSchema("xdr_get_schema", { table: "DeviceInfo" });

    expect(text).toContain("BrandNewColumn");
    expect(text).toContain("Not in the bundled documentation snapshot");
    // Columns the docs list but this tenant did not return are named, not silently dropped.
    expect(text).toContain("documentedNotInTenant");
    expect(text).toContain('"fromCache": false');
    expect(fetchMock.mock.calls.some(([url]) => url.includes("/security/runHuntingQuery"))).toBe(true);
  });

  it("serves the second lookup of the same table from the cache", async () => {
    await signedIn();
    stubNetwork(tenantColumns([{ name: "DeviceId", type: "String" }]));
    const getSchema = await connect();

    await getSchema("xdr_get_schema", { table: "DeviceInfo" });
    expect(await getSchema("xdr_get_schema", { table: "DeviceInfo" })).toContain('"fromCache": true');
  });

  it("describes a table that exists in the tenant but not in the documentation", async () => {
    await signedIn();
    stubNetwork(tenantColumns([{ name: "TimeGenerated", type: "DateTime" }]));
    const getSchema = await connect();

    const text = await getSchema("xdr_get_schema", { table: "Custom_Telemetry_CL" });

    expect(text).toContain('"status": "tenant-only"');
    expect(text).toContain("TimeGenerated");
  });

  it("falls back to the documentation, with the reason, when the tenant cannot be asked", async () => {
    await signedIn();
    stubNetwork(() => new Response(JSON.stringify({ error: { message: "bad request" } }), { status: 400 }));
    const getSchema = await connect();

    const text = await getSchema("xdr_get_schema", { table: "DeviceInfo" });

    expect(text).toContain("DeviceId");
    expect(text).toContain('"status": "unavailable"');
    expect(text).toContain("can lag your tenant");
  });

  it("says the plugin is unconfigured without dragging the model into configuring it", async () => {
    delete process.env.XDR_TENANT_ID;
    delete process.env.XDR_CLIENT_ID;
    const fetchMock = stubNetwork(tenantColumns([]));
    const getSchema = await connect();

    const text = await getSchema("xdr_get_schema", { table: "DeviceInfo" });

    expect(text).toContain("not configured yet");
    expect(text).not.toContain("GUIDs");
    expect(text).toContain("DeviceId");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("stays entirely offline when live is false", async () => {
    await signedIn();
    const fetchMock = stubNetwork(tenantColumns([{ name: "DeviceId", type: "String" }]));
    const getSchema = await connect();

    const text = await getSchema("xdr_get_schema", { table: "DeviceInfo", live: false });

    expect(text).toContain("DeviceId");
    expect(text).not.toContain("liveVerification");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("searches the cached tenant columns alongside the documentation, without querying", async () => {
    await signedIn();
    const fetchMock = stubNetwork(tenantColumns([{ name: "RiskLevelDuringSignIn", type: "Int32" }]));
    const getSchema = await connect();
    await getSchema("xdr_get_schema", { table: "EntraIdSignInEvents" });
    const callsAfterDescribe = fetchMock.mock.calls.length;

    const text = await getSchema("xdr_get_schema", { search: "risk level during" });

    expect(text).toContain("cachedTenantMatches");
    expect(text).toContain("RiskLevelDuringSignIn");
    expect(fetchMock.mock.calls.length).toBe(callsAfterDescribe);
  });

  it("reports an unknown table with the closest documented names", async () => {
    await signedIn();
    stubNetwork(() => new Response(JSON.stringify({ error: { message: "unknown table" } }), { status: 400 }));
    const getSchema = await connect();

    const text = await getSchema("xdr_get_schema", { table: "DeviceProcess" });

    expect(text).toContain('Unknown Defender XDR table "DeviceProcess"');
    expect(text).toContain("DeviceProcessEvents");
  });

  // The bug this feature exists to prevent: a session ran a hunting query, nothing warmed the
  // cache, and the next schema question fell back to documentation months out of date.
  it("caches the columns of the tables a hunting query read", async () => {
    await signedIn();
    const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
      if (url.includes("/oauth2/v2.0/token")) {
        return new Response(JSON.stringify({ access_token: "access", expires_in: 3600 }), { status: 200 });
      }
      const query = JSON.parse(String(init.body)).Query as string;
      return query.endsWith("| take 0")
        ? new Response(JSON.stringify({ schema: [{ name: "RiskLevelDuringSignIn", type: "Int32" }], results: [] }), { status: 200 })
        : new Response(JSON.stringify({ schema: [{ name: "Total", type: "Int64" }], results: [{ Total: 3 }] }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const call = await connect();

    await call("xdr_run_query", { query: "EntraIdSignInEvents | summarize Total = count()" });

    // The warming probe is not awaited by the query, so wait for it to land.
    await eventually(async () => (await call("xdr_get_schema", { search: "risk level during" })).includes("cachedTenantMatches"));
    const searched = await call("xdr_get_schema", { search: "risk level during" });
    expect(searched).toContain("RiskLevelDuringSignIn");
    expect(searched).toContain("EntraIdSignInEvents");
    expect(fetchMock.mock.calls.filter(([, init]) => String(init?.body).includes("take 0")).length).toBe(1);
  });

  it("rejects refresh without a table, and table with search", async () => {
    const getSchema = await connect();

    expect(await getSchema("xdr_get_schema", { refresh: true })).toContain("refresh applies only to an exact table");
    expect(await getSchema("xdr_get_schema", { table: "DeviceInfo", search: "device" })).toContain("Pass either table or search");
  });
});

describe("a rejected hunting query", () => {
  /**
   * Answers schema probes with columns and everything else with a semantic rejection, which
   * is the shape of the real failure this exists for: KQL written against a column the
   * tenant does not have.
   */
  function stubRejectingTenant(columnsByTable: Record<string, { name: string; type: string }[]>) {
    const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
      if (url.includes("/oauth2/v2.0/token")) {
        return new Response(JSON.stringify({ access_token: "access", expires_in: 3600 }), { status: 200 });
      }
      const query = JSON.parse(String(init.body)).Query as string;
      if (query.endsWith("| take 0")) {
        const columns = columnsByTable[query.split("\n")[0]!.trim()];
        return columns
          ? new Response(JSON.stringify({ schema: columns, results: [] }), { status: 200 })
          : new Response(JSON.stringify({ error: { message: "Failed to resolve table" } }), { status: 400 });
      }
      return new Response(
        JSON.stringify({ error: { message: "Failed to resolve column or scalar expression named 'IsInteractive'" } }),
        { status: 400 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  // The regression this guards: a failed query used to send the model to xdr_get_schema for
  // the columns, costing a round-trip that the error itself can carry.
  it("answers with the tenant's columns for the tables the query referenced", async () => {
    await signedIn();
    stubRejectingTenant({ EntraIdSignInEvents: [{ name: "LogonType", type: "String" }] });
    const call = await connect();

    const text = await call("xdr_run_query", { query: "EntraIdSignInEvents | where IsInteractive == true" });

    expect(text).toContain("Failed to resolve column");
    expect(text).toContain("The tenant's columns for the tables this query referenced");
    expect(text).toContain("LogonType (String)");
    expect(text).not.toContain("check it with xdr_get_schema");
  });

  it("carries a retired table's replacement, with the replacement's own columns", async () => {
    await signedIn();
    stubRejectingTenant({
      AADSignInEventsBeta: [{ name: "Timestamp", type: "DateTime" }],
      EntraIdSignInEvents: [{ name: "LogonType", type: "String" }],
    });
    const call = await connect();

    const text = await call("xdr_run_query", { query: "AADSignInEventsBeta | where IsInteractive == true" });

    expect(text).toContain("AADSignInEventsBeta (retired, replaced by EntraIdSignInEvents)");
    expect(text).toContain("EntraIdSignInEvents: LogonType (String)");
  });

  it("caches the columns it fetched, so the correction path never probes twice", async () => {
    await signedIn();
    const fetchMock = stubRejectingTenant({ EntraIdSignInEvents: [{ name: "LogonType", type: "String" }] });
    const call = await connect();

    await call("xdr_run_query", { query: "EntraIdSignInEvents | where IsInteractive == true" });
    const described = await call("xdr_get_schema", { table: "EntraIdSignInEvents" });

    expect(described).toContain('"fromCache": true');
    expect(fetchMock.mock.calls.filter(([, init]) => String(init?.body).includes("take 0")).length).toBe(1);
  });

  it("still names the schema tool when no referenced table could be answered", async () => {
    await signedIn();
    stubRejectingTenant({});
    const call = await connect();

    const text = await call("xdr_run_query", { query: "NoSuchTableAnywhere | take 1" });

    expect(text).toContain("check it with xdr_get_schema");
  });
});
