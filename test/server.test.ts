import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeOwnerOnlyDir, stateDir } from "../src/config.js";
import { clientSignInPrompt, createServer } from "../src/server.js";

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

describe("clientSignInPrompt", () => {
  /** Stands in for the low-level Server, recording what the client was asked to show. */
  function fake(capabilities: unknown) {
    const sent: Array<Record<string, unknown>> = [];
    const prompt = clientSignInPrompt({
      server: {
        getClientCapabilities: () => capabilities,
        elicitInput: async (params: Record<string, unknown>) => {
          sent.push(params);
          return { action: "accept" };
        },
        createElicitationCompletionNotifier: () => async () => {},
      },
    } as never);
    return { prompt, sent };
  }

  // Claude Code 2.1.238 advertises form mode only, and answers a URL elicitation with
  // "Client does not support url elicitation." Asking anyway wastes a round trip and leaves
  // the person staring at nothing while the request is refused.
  it("does not hand a URL to a client that only advertises form mode", () => {
    const { prompt, sent } = fake({ elicitation: { form: {} } });
    expect(prompt.handOff("https://login.example/authorize?a=1", "id-1")).toBeUndefined();
    expect(sent).toEqual([]);
  });

  it("does not hand a URL to a client with no elicitation at all", () => {
    const { prompt, sent } = fake({ roots: { listChanged: true } });
    expect(prompt.handOff("https://login.example/authorize?a=1", "id-1")).toBeUndefined();
    expect(sent).toEqual([]);
  });

  it("hands the URL over once a client advertises url mode", async () => {
    const { prompt, sent } = fake({ elicitation: { form: {}, url: {} } });
    const handoff = prompt.handOff("https://login.example/authorize?a=1&b=2", "id-2");
    expect(handoff).toBeDefined();
    await expect(handoff!.answered).resolves.toEqual({ action: "accept" });
    expect(sent).toEqual([
      {
        mode: "url",
        message: expect.stringContaining("Sign in to Microsoft Defender XDR"),
        url: "https://login.example/authorize?a=1&b=2",
        elicitationId: "id-2",
      },
    ]);
  });
});
