import { randomBytes } from "node:crypto";
import { mkdtemp, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Client,
  isInputRequiredResult,
  ProtocolError,
  StreamableHTTPClientTransport,
  type CallToolResult,
  type ClientCapabilities,
  type InputRequiredResult,
} from "@modelcontextprotocol/client";
import { createMcpHandler, createRequestStateCodec, type ServerContext } from "@modelcontextprotocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeOwnerOnlyDir, stateDir } from "../src/config.js";
import { createServer, createServerRuntime, type ServerRuntime } from "../src/server.js";

const TENANT = "11111111-1111-1111-1111-111111111111";
const APP = "22222222-2222-2222-2222-222222222222";
const RESPONSE_KEY = "defender-sign-in";
const nativeFetch = globalThis.fetch.bind(globalThis);
const saved = { ...process.env };

beforeEach(async () => {
  process.env.XDG_CONFIG_HOME = await mkdtemp(join(tmpdir(), "xdr-mrtr-"));
  process.env.XDR_TENANT_ID = TENANT;
  process.env.XDR_CLIENT_ID = APP;
});

afterEach(() => {
  process.env = { ...saved };
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function idToken(username = "analyst@example.com"): string {
  return `header.${Buffer.from(JSON.stringify({ preferred_username: username })).toString("base64url")}.signature`;
}

function stubMicrosoft(hunting?: (query: string) => Response) {
  const fetchMock = vi.fn(async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.includes("/oauth2/v2.0/token")) {
      return new Response(
        JSON.stringify({
          access_token: "access",
          refresh_token: "refresh",
          expires_in: 3600,
          id_token: idToken(),
        }),
        { status: 200 },
      );
    }
    if (url.includes("/security/runHuntingQuery")) {
      const query = JSON.parse(String(init.body)).Query as string;
      return hunting?.(query) ?? new Response(JSON.stringify({ schema: [], results: [] }), { status: 200 });
    }
    throw new Error(`unexpected request to ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function signedIn(): Promise<void> {
  const directory = stateDir();
  await makeOwnerOnlyDir(directory);
  await writeFile(
    join(directory, "token.json"),
    JSON.stringify({ refreshToken: "refresh", username: "analyst@example.com", tenantId: TENANT, clientId: APP }),
  );
}

interface ModernConnection {
  client: Client;
  runtime: ServerRuntime;
  close(): Promise<void>;
}

async function connectModern(options: {
  capabilities?: ClientCapabilities;
  browserOpener?: (url: string) => void;
  autoFulfill?: boolean;
} = {}): Promise<ModernConnection> {
  const runtime = createServerRuntime({ browserOpener: options.browserOpener ?? vi.fn() });
  const handler = createMcpHandler(() => createServer({ runtime }), { legacy: "reject", onerror: () => {} });
  const transport = new StreamableHTTPClientTransport(new URL("http://test.local/mcp"), {
    fetch: (url, init) => handler.fetch(new Request(url, init)),
  });
  const client = new Client(
    { name: "xdr-modern-test", version: "1.0.0" },
    {
      versionNegotiation: { mode: { pin: "2026-07-28" } },
      capabilities: options.capabilities,
      inputRequired: { autoFulfill: options.autoFulfill ?? false },
    },
  );
  await client.connect(transport);
  return {
    client,
    runtime,
    close: async () => {
      await client.close();
      await handler.close();
    },
  };
}

async function manualToolCall(
  client: Client,
  name: string,
  args: Record<string, unknown>,
  retry?: { requestState: string; action: "accept" | "decline" | "cancel" },
): Promise<CallToolResult | InputRequiredResult> {
  return (await client.request(
    {
      method: "tools/call",
      params: {
        name,
        arguments: args,
        ...(retry
          ? {
              requestState: retry.requestState,
              inputResponses: { [RESPONSE_KEY]: { action: retry.action } },
            }
          : {}),
      },
    },
    { allowInputRequired: true },
  )) as CallToolResult | InputRequiredResult;
}

function asInputRequired(value: CallToolResult | InputRequiredResult): InputRequiredResult {
  expect(isInputRequiredResult(value)).toBe(true);
  return value as InputRequiredResult;
}

function authorizationUrl(round: InputRequiredResult): string {
  const entry = round.inputRequests?.[RESPONSE_KEY];
  expect(entry?.method).toBe("elicitation/create");
  return String((entry?.params as { url?: unknown }).url);
}

function statePayload(requestState: string): {
  attemptId: string;
  flowId: string;
  purpose: string;
  tenantId: string;
  clientId: string;
} {
  const body = JSON.parse(Buffer.from(requestState.split(".")[1]!, "base64url").toString()) as { p: unknown };
  return body.p as ReturnType<typeof statePayload>;
}

async function completeAuthorization(url: string): Promise<Response> {
  const authorize = new URL(url);
  const callback = new URL(authorize.searchParams.get("redirect_uri")!);
  callback.hostname = "127.0.0.1";
  callback.search = new URLSearchParams({
    code: "authorization-code",
    state: authorize.searchParams.get("state")!,
  }).toString();
  return await nativeFetch(callback);
}

const urlCapability = { elicitation: { url: {} } } satisfies ClientCapabilities;

describe("Defender sign-in over modern MCP", () => {
  it("returns input_required, accepts the URL response, and does not repeat login configuration", async () => {
    stubMicrosoft();
    const { client, close } = await connectModern({ capabilities: urlCapability });
    const args = { tenant_id: TENANT, client_id: APP };

    const first = asInputRequired(await manualToolCall(client, "xdr_login", args));
    expect(first.requestState).toBeTypeOf("string");
    const configFile = join(stateDir(), "config.json");
    const savedAt = (await stat(configFile)).mtimeMs;

    expect((await completeAuthorization(authorizationUrl(first))).status).toBe(200);
    await new Promise(resolve => setTimeout(resolve, 15));
    const final = await manualToolCall(client, "xdr_login", args, {
      requestState: first.requestState!,
      action: "accept",
    });

    expect(isInputRequiredResult(final)).toBe(false);
    expect((final as CallToolResult).content[0]).toMatchObject({
      type: "text",
      text: expect.stringContaining("Signed in to Defender XDR as analyst@example.com"),
    });
    expect((await stat(configFile)).mtimeMs).toBe(savedAt);

    const replay = await manualToolCall(client, "xdr_login", args, {
      requestState: first.requestState!,
      action: "accept",
    });
    expect((replay as CallToolResult).isError).toBe(true);
    expect((replay as CallToolResult).content[0]).toMatchObject({
      type: "text",
      text: expect.stringContaining("already consumed"),
    });
    await close();
  });

  it("lets the v2 client fulfil URL elicitation and retry automatically", async () => {
    stubMicrosoft();
    const { client, close } = await connectModern({ capabilities: urlCapability, autoFulfill: true });
    const seen: string[] = [];
    client.setRequestHandler("elicitation/create", async request => {
      const url = String((request.params as { url?: unknown }).url);
      seen.push(url);
      expect((await completeAuthorization(url)).status).toBe(200);
      return { action: "accept" };
    });

    const result = await client.callTool({ name: "xdr_login", arguments: {} });

    expect(seen).toHaveLength(1);
    expect(result.content[0]).toMatchObject({ type: "text", text: expect.stringContaining("Signed in") });
    await close();
  });

  it("reissues the same URL when a retry omits the input response", async () => {
    stubMicrosoft();
    const { client, close } = await connectModern({ capabilities: urlCapability });
    const first = asInputRequired(await manualToolCall(client, "xdr_login", {}));
    const second = asInputRequired(
      (await client.request(
        {
          method: "tools/call",
          params: { name: "xdr_login", arguments: {}, requestState: first.requestState },
        },
        { allowInputRequired: true },
      )) as CallToolResult | InputRequiredResult,
    );

    expect(authorizationUrl(second)).toBe(authorizationUrl(first));
    expect(statePayload(second.requestState!).attemptId).toBe(statePayload(first.requestState!).attemptId);
    expect(statePayload(second.requestState!).flowId).toBe(statePayload(first.requestState!).flowId);

    await manualToolCall(client, "xdr_login", {}, { requestState: second.requestState!, action: "cancel" });
    await close();
  });

  it.each(["decline", "cancel"] as const)("stops the attempt when the client answers %s", async action => {
    stubMicrosoft();
    const { client, close } = await connectModern({ capabilities: urlCapability });
    const first = asInputRequired(await manualToolCall(client, "xdr_login", {}));
    const final = await manualToolCall(client, "xdr_login", {}, { requestState: first.requestState!, action });

    expect((final as CallToolResult).isError).toBe(true);
    expect((final as CallToolResult).content[0]).toMatchObject({
      type: "text",
      text: expect.stringMatching(action === "decline" ? /declined/ : /cancelled/),
    });
    await expect(completeAuthorization(authorizationUrl(first))).rejects.toThrow();
    await close();
  });

  it("rejects tampered requestState before resuming the handler", async () => {
    stubMicrosoft();
    const { client, runtime, close } = await connectModern({ capabilities: urlCapability });
    const first = asInputRequired(await manualToolCall(client, "xdr_login", {}));

    await expect(
      manualToolCall(client, "xdr_login", {}, { requestState: `${first.requestState!}x`, action: "accept" }),
    ).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(ProtocolError);
      expect((error as Error).message).toMatch(/Invalid or expired requestState/);
      return true;
    });

    runtime.auth().cancelSignIn(statePayload(first.requestState!).attemptId);
    await close();
  });

  it("uses the local browser fallback when URL elicitation is absent", async () => {
    stubMicrosoft();
    let opened!: (url: string) => void;
    const openedUrl = new Promise<string>(resolve => {
      opened = resolve;
    });
    const browserOpener = vi.fn((url: string) => opened(url));
    const { client, close } = await connectModern({ capabilities: { elicitation: { form: {} } }, browserOpener });

    const call = client.callTool({ name: "xdr_login", arguments: {} });
    const url = await openedUrl;
    expect((await completeAuthorization(url)).status).toBe(200);
    const result = await call;

    expect(browserOpener).toHaveBeenCalledOnce();
    expect(result.content[0]).toMatchObject({ type: "text", text: expect.stringContaining("Signed in") });
    await close();
  });
});

describe("automatic query sign-in", () => {
  it("signs in through MRTR and then runs the original query once", async () => {
    const query = "DeviceInfo | take 1";
    const fetchMock = stubMicrosoft(value =>
      value.endsWith("| take 0")
        ? new Response(JSON.stringify({ schema: [{ name: "DeviceId", type: "String" }], results: [] }), { status: 200 })
        : new Response(
            JSON.stringify({ schema: [{ name: "DeviceId", type: "String" }], results: [{ DeviceId: "device-1" }] }),
            { status: 200 },
          ),
    );
    const { client, close } = await connectModern({ capabilities: urlCapability });

    const first = asInputRequired(await manualToolCall(client, "xdr_run_query", { query }));
    expect(statePayload(first.requestState!).purpose).toBe("xdr-run-query");
    expect((await completeAuthorization(authorizationUrl(first))).status).toBe(200);
    const final = await manualToolCall(
      client,
      "xdr_run_query",
      { query },
      { requestState: first.requestState!, action: "accept" },
    );

    expect((final as CallToolResult).content[0]).toMatchObject({ type: "text", text: expect.stringContaining("device-1") });
    const originalCalls = fetchMock.mock.calls.filter(([, init]) => {
      if (!String(init?.body).includes("Query")) return false;
      return (JSON.parse(String(init?.body)).Query as string) === query;
    });
    expect(originalCalls).toHaveLength(1);
    await close();
  });

  it("skips MRTR when silent refresh succeeds", async () => {
    await signedIn();
    const fetchMock = stubMicrosoft(() =>
      new Response(JSON.stringify({ schema: [{ name: "Count", type: "Int64" }], results: [{ Count: 1 }] }), {
        status: 200,
      }),
    );
    const { client, close } = await connectModern({ capabilities: urlCapability, autoFulfill: true });
    const elicitation = vi.fn(async () => ({ action: "accept" as const }));
    client.setRequestHandler("elicitation/create", elicitation);

    const result = await client.callTool({ name: "xdr_run_query", arguments: { query: "DeviceInfo | count" } });

    expect(result.content[0]).toMatchObject({ type: "text", text: expect.stringContaining('"Count": 1') });
    expect(elicitation).not.toHaveBeenCalled();
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/oauth2/v2.0/token"))).toBe(true);
    await close();
  });

  it("shares one pending attempt across parallel first-use queries", async () => {
    stubMicrosoft();
    const { client, close } = await connectModern({ capabilities: urlCapability });

    const [one, two] = await Promise.all([
      manualToolCall(client, "xdr_run_query", { query: "DeviceInfo | take 1" }),
      manualToolCall(client, "xdr_run_query", { query: "DeviceInfo | take 2" }),
    ]);
    const first = asInputRequired(one);
    const second = asInputRequired(two);
    const firstState = statePayload(first.requestState!);
    const secondState = statePayload(second.requestState!);

    expect(firstState.attemptId).toBe(secondState.attemptId);
    expect(firstState.flowId).not.toBe(secondState.flowId);
    expect(authorizationUrl(first)).toBe(authorizationUrl(second));

    await manualToolCall(
      client,
      "xdr_run_query",
      { query: "DeviceInfo | take 1" },
      { requestState: first.requestState!, action: "decline" },
    );
    await close();
  });
});

describe("silent schema authentication", () => {
  it("returns documented schema while signed out without eliciting, opening a browser, or calling Microsoft", async () => {
    const browserOpener = vi.fn();
    const fetchMock = vi.fn(async () => {
      throw new Error("schema lookup must stay offline while signed out");
    });
    vi.stubGlobal("fetch", fetchMock);
    const { client, close } = await connectModern({
      capabilities: urlCapability,
      browserOpener,
      autoFulfill: true,
    });
    const elicitation = vi.fn(async () => ({ action: "accept" as const }));
    client.setRequestHandler("elicitation/create", elicitation);

    const result = await client.callTool({ name: "xdr_get_schema", arguments: { table: "DeviceInfo" } });
    const text = result.content[0]?.type === "text" ? result.content[0].text : "";

    expect(text).toContain("DeviceId");
    expect(text).toContain("No Defender XDR sign-in is cached");
    expect(elicitation).not.toHaveBeenCalled();
    expect(browserOpener).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    await close();
  });

  it("reports an expired grant without starting an interactive sign-in", async () => {
    await signedIn();
    const browserOpener = vi.fn();
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.includes("/oauth2/v2.0/token")) {
        return new Response(
          JSON.stringify({ error: "invalid_grant", error_description: "AADSTS50173: The grant expired." }),
          { status: 400 },
        );
      }
      throw new Error(`unexpected request to ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const { client, close } = await connectModern({ capabilities: urlCapability, browserOpener, autoFulfill: true });
    const elicitation = vi.fn(async () => ({ action: "accept" as const }));
    client.setRequestHandler("elicitation/create", elicitation);

    const result = await client.callTool({ name: "xdr_get_schema", arguments: { table: "DeviceInfo" } });
    const text = result.content[0]?.type === "text" ? result.content[0].text : "";

    expect(text).toContain("saved sign-in is no longer valid");
    expect(text).toContain("DeviceId");
    expect(elicitation).not.toHaveBeenCalled();
    expect(browserOpener).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledOnce();
    await close();
  });
});

describe("request state codec", () => {
  it("rejects an expired signed payload", async () => {
    const codec = createRequestStateCodec({ key: randomBytes(32), ttlSeconds: 1 });
    const ctx = {} as ServerContext;
    const state = await codec.mint({ purpose: "test" });

    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 2_000);
    await expect(codec.verify(state, ctx)).rejects.toThrow("expired");
    vi.useRealTimers();
  });
});
