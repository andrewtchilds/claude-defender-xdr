import { spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { describe, expect, it } from "vitest";

const serverPath = join(process.cwd(), "dist/server.js");

async function childEnvironment(): Promise<Record<string, string>> {
  return {
    ...Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined)),
    XDG_CONFIG_HOME: await mkdtemp(join(tmpdir(), "xdr-stdio-")),
    XDR_TENANT_ID: "11111111-1111-1111-1111-111111111111",
    XDR_CLIENT_ID: "22222222-2222-2222-2222-222222222222",
  };
}

describe("production stdio entry", () => {
  it("lists and executes all four tools over protocol revision 2026-07-28", async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [serverPath],
      env: await childEnvironment(),
      stderr: "pipe",
    });
    const client = new Client(
      { name: "stdio-integration-test", version: "1.0.0" },
      {
        versionNegotiation: { mode: { pin: "2026-07-28" } },
        capabilities: { elicitation: { url: {} } },
      },
    );
    const elicitations: string[] = [];
    client.setRequestHandler("elicitation/create", async request => {
      elicitations.push(String((request.params as { url?: unknown }).url));
      return { action: "decline" };
    });

    try {
      await client.connect(transport);
      const listed = await client.listTools();

      expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
      expect(listed.tools.map(tool => tool.name)).toEqual([
        "xdr_login",
        "xdr_logout",
        "xdr_run_query",
        "xdr_get_schema",
      ]);
      for (const tool of listed.tools) expect(tool.inputSchema.type).toBe("object");
      const queryTool = listed.tools.find(tool => tool.name === "xdr_run_query")!;
      expect((queryTool.inputSchema.properties?.query as { description?: string }).description).toContain("KQL");

      const login = await client.callTool({ name: "xdr_login", arguments: {} });
      expect(login.isError).toBe(true);
      expect(login.content[0]).toMatchObject({ type: "text", text: expect.stringContaining("declined") });

      const query = await client.callTool({ name: "xdr_run_query", arguments: { query: "DeviceInfo | take 1" } });
      expect(query.isError).toBe(true);
      expect(query.content[0]).toMatchObject({ type: "text", text: expect.stringContaining("declined") });

      const schema = await client.callTool({ name: "xdr_get_schema", arguments: { table: "DeviceInfo", live: false } });
      expect(schema.content[0]).toMatchObject({ type: "text", text: expect.stringContaining("DeviceId") });

      const logout = await client.callTool({ name: "xdr_logout", arguments: {} });
      expect(logout.isError).not.toBe(true);
      expect(logout.content[0]).toMatchObject({ type: "text", text: expect.stringContaining("No Defender XDR sign-in") });
      expect(elicitations).toHaveLength(2);
    } finally {
      await client.close();
    }
  });

  it("rejects a 2025 initialize opening", async () => {
    const child = spawn(process.execPath, [serverPath], {
      env: await childEnvironment(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    const lines = createInterface({ input: child.stdout });
    const response = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("stdio server did not answer initialize")), 5_000);
      lines.once("line", line => {
        clearTimeout(timer);
        resolve(line);
      });
      child.once("error", reject);
    });

    try {
      child.stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "legacy-test", version: "1.0.0" },
          },
        })}\n`,
      );
      const message = JSON.parse(await response) as {
        error?: { code?: number; message?: string; data?: { supported?: string[] } };
      };

      expect(message.error?.code).toBe(-32022);
      expect(message.error?.message).toContain("Unsupported protocol version");
      expect(message.error?.data?.supported).toEqual(["2026-07-28"]);
    } finally {
      lines.close();
      child.stdin.end();
      child.kill();
    }
  });
});
