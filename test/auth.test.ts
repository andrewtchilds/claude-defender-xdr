import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Authenticator, browserOpeners, NotSignedInError } from "../src/auth.js";
import type { SignInAttempt } from "../src/auth.js";
import type { Config } from "../src/config.js";

const config = {
  tenantId: "31e14793-1820-4e78-bb77-295ff38db016",
  clientId: "c121ae43-424f-4d07-ba0d-c5e36b6538bb",
  graphBaseUrl: "https://graph.microsoft.com",
  loginBaseUrl: "https://login.microsoftonline.com",
  maxRows: 1000,
  defaultTimespan: "7d",
} satisfies Config;

const saved = { ...process.env };
let directory: string;

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), "xdr-auth-"));
  process.env.XDG_CONFIG_HOME = directory;
});

afterEach(() => {
  process.env = { ...saved };
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const tokenPath = () => join(directory, "claude-defender-xdr", "token.json");

/** Writes the refresh token a signed-in user would already have. */
async function cachedSignIn(): Promise<void> {
  await mkdir(join(directory, "claude-defender-xdr"), { recursive: true });
  await writeFile(
    tokenPath(),
    JSON.stringify({
      refreshToken: "refresh",
      username: "analyst@example.com",
      tenantId: config.tenantId,
      clientId: config.clientId,
    }),
  );
}

function idToken(username = "analyst@example.com"): string {
  return `header.${Buffer.from(JSON.stringify({ preferred_username: username })).toString("base64url")}.signature`;
}

/** Lets loopback callbacks use real fetch while mocking Entra token requests. */
function stubTokenEndpoint(
  response: () => Response = () =>
    new Response(
      JSON.stringify({
        access_token: "access",
        refresh_token: "refresh",
        expires_in: 3600,
        id_token: idToken(),
      }),
      { status: 200 },
    ),
) {
  const nativeFetch = globalThis.fetch.bind(globalThis);
  const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.startsWith("http://127.0.0.1:")) return await nativeFetch(input, init);
    if (url.includes("/oauth2/v2.0/token")) return response();
    throw new Error(`unexpected request to ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function callbackUrl(attempt: SignInAttempt, params: Record<string, string>): URL {
  const authorize = new URL(attempt.authorizationUrl);
  const callback = new URL(authorize.searchParams.get("redirect_uri")!);
  callback.hostname = "127.0.0.1";
  callback.search = new URLSearchParams(params).toString();
  return callback;
}

async function completeCallback(attempt: SignInAttempt, code = "authorization-code"): Promise<Response> {
  const authorize = new URL(attempt.authorizationUrl);
  return await fetch(
    callbackUrl(attempt, {
      code,
      state: authorize.searchParams.get("state")!,
    }),
  );
}

describe("pending interactive sign-in", () => {
  it("returns only after binding a loopback listener on a real ephemeral port", async () => {
    const auth = new Authenticator(config, { browserOpener: vi.fn() });
    const attempt = await auth.startSignIn();
    const authorize = new URL(attempt.authorizationUrl);
    const redirect = new URL(authorize.searchParams.get("redirect_uri")!);

    expect(redirect.hostname).toBe("localhost");
    expect(Number(redirect.port)).toBeGreaterThan(0);
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorize.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authorize.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(authorize.searchParams.get("prompt")).toBe("select_account");

    const cancelled = expect(auth.waitForSignIn(attempt.attemptId)).rejects.toThrow(/cancelled/);
    auth.cancelSignIn(attempt.attemptId);
    await cancelled;
  });

  it("exchanges a valid callback, stores the refresh token, and completes with the username", async () => {
    const fetchMock = stubTokenEndpoint();
    const auth = new Authenticator(config, { browserOpener: vi.fn() });
    const attempt = await auth.startSignIn();
    const waiting = auth.waitForSignIn(attempt.attemptId);

    expect((await completeCallback(attempt)).status).toBe(200);
    await expect(waiting).resolves.toBe("analyst@example.com");
    await expect(readFile(tokenPath(), "utf8")).resolves.toContain('"refreshToken": "refresh"');

    const tokenCall = fetchMock.mock.calls.find(([input]) => String(input).includes("/oauth2/v2.0/token"))!;
    const form = new URLSearchParams(String(tokenCall[1]?.body));
    expect(form.get("code")).toBe("authorization-code");
    expect(form.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(form.get("redirect_uri")).toMatch(/^http:\/\/localhost:\d+$/);
  });

  it("rejects invalid state and closes the listener", async () => {
    stubTokenEndpoint();
    const auth = new Authenticator(config, { browserOpener: vi.fn() });
    const attempt = await auth.startSignIn();
    const waiting = expect(auth.waitForSignIn(attempt.attemptId)).rejects.toThrow(/state validation/);

    expect((await fetch(callbackUrl(attempt, { code: "code", state: "wrong" }))).status).toBe(400);
    await waiting;
    await expect(fetch(callbackUrl(attempt, { code: "again", state: "wrong" }))).rejects.toThrow();
  });

  it("reports Entra callback errors without attempting a token exchange", async () => {
    const fetchMock = stubTokenEndpoint();
    const auth = new Authenticator(config, { browserOpener: vi.fn() });
    const attempt = await auth.startSignIn();
    const authorize = new URL(attempt.authorizationUrl);
    const waiting = expect(auth.waitForSignIn(attempt.attemptId)).rejects.toThrow("The operator declined.");

    const response = await fetch(
      callbackUrl(attempt, {
        error: "access_denied",
        error_description: "The operator declined.\nTrace ID: 1",
        state: authorize.searchParams.get("state")!,
      }),
    );

    expect(response.status).toBe(400);
    await waiting;
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/oauth2/v2.0/token"))).toBe(false);
  });

  it("closes and rejects on cancellation", async () => {
    const auth = new Authenticator(config, { browserOpener: vi.fn() });
    const attempt = await auth.startSignIn();
    const waiting = expect(auth.waitForSignIn(attempt.attemptId)).rejects.toThrow(/declined/);

    auth.cancelSignIn(attempt.attemptId, "Sign-in was declined.");

    await waiting;
    expect(auth.signInAttempt(attempt.attemptId)).toBeUndefined();
    await expect(fetch(callbackUrl(attempt, { code: "late", state: "late" }))).rejects.toThrow();
  });

  it("closes and rejects when the token exchange fails", async () => {
    stubTokenEndpoint(
      () =>
        new Response(JSON.stringify({ error: "invalid_grant", error_description: "The authorization code expired." }), {
          status: 400,
        }),
    );
    const auth = new Authenticator(config, { browserOpener: vi.fn() });
    const attempt = await auth.startSignIn();
    const waiting = expect(auth.waitForSignIn(attempt.attemptId)).rejects.toThrow(/authorization code expired/);

    expect((await completeCallback(attempt)).status).toBe(200);
    await waiting;
  });

  it("times out and allows a later attempt", async () => {
    const auth = new Authenticator(config, { browserOpener: vi.fn(), signInTimeoutMs: 20 });
    const first = await auth.startSignIn();
    const waiting = expect(auth.waitForSignIn(first.attemptId)).rejects.toThrow(/Timed out/);

    await waiting;
    const second = await auth.startSignIn();
    expect(second.attemptId).not.toBe(first.attemptId);
    auth.cancelSignIn(second.attemptId);
  });

  it("collapses concurrent callers into one listener and attempt", async () => {
    const auth = new Authenticator(config, { browserOpener: vi.fn() });
    const attempts = await Promise.all([auth.startSignIn(), auth.startSignIn(), auth.startSignIn()]);

    expect(new Set(attempts.map(attempt => attempt.attemptId))).toHaveLength(1);
    auth.cancelSignIn(attempts[0]!.attemptId);
  });

  it("does not let a failed attempt poison the next one", async () => {
    const auth = new Authenticator(config, { browserOpener: vi.fn() });
    const first = await auth.startSignIn();
    const failed = expect(auth.waitForSignIn(first.attemptId)).rejects.toThrow(/first failed/);
    auth.cancelSignIn(first.attemptId, "first failed");
    await failed;

    const second = await auth.startSignIn();
    expect(second.attemptId).not.toBe(first.attemptId);
    auth.cancelSignIn(second.attemptId);
  });

  it("opens the fallback browser exactly once and writes nothing to stdout", async () => {
    const opener = vi.fn();
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const auth = new Authenticator(config, { browserOpener: opener });
    const attempt = await auth.startSignIn();

    auth.openSignInInBrowser(attempt.attemptId);
    auth.openSignInInBrowser(attempt.attemptId);

    expect(opener).toHaveBeenCalledOnce();
    expect(opener).toHaveBeenCalledWith(attempt.authorizationUrl);
    expect(stdout).not.toHaveBeenCalled();
    auth.cancelSignIn(attempt.attemptId);
  });
});

describe("refreshing the cached sign-in", () => {
  it("reports a missing saved sign-in without starting an interactive attempt", async () => {
    const opener = vi.fn();
    const auth = new Authenticator(config, { browserOpener: opener });

    await expect(auth.accessTokenSilent()).rejects.toBeInstanceOf(NotSignedInError);
    expect(opener).not.toHaveBeenCalled();
  });

  // The regression this guards: a laptop that was briefly offline used to lose its saved
  // sign-in, because every refresh failure was treated as a dead grant and deleted the token.
  it("keeps the saved sign-in when Entra is unreachable", async () => {
    await cachedSignIn();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("fetch failed");
      }),
    );

    await expect(new Authenticator(config).accessTokenSilent()).rejects.toThrow(/Could not reach Microsoft Entra/);
    await expect(readFile(tokenPath(), "utf8")).resolves.toContain("refresh");
  });

  it("keeps the saved sign-in when the token endpoint answers 5xx", async () => {
    await cachedSignIn();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "temporarily_unavailable" }), { status: 503 })),
    );

    await expect(new Authenticator(config).accessTokenSilent()).rejects.toThrow(/temporarily_unavailable/);
    await expect(readFile(tokenPath(), "utf8")).resolves.toContain("refresh");
  });

  it("drops the saved sign-in once Entra pronounces the grant dead", async () => {
    await cachedSignIn();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              error: "invalid_grant",
              error_description: "AADSTS50173: The provided grant has expired.\nTrace ID: 1",
            }),
            { status: 400 },
          ),
      ),
    );

    await expect(new Authenticator(config).accessTokenSilent()).rejects.toThrow(/no longer valid.*AADSTS50173/);
    await expect(readFile(tokenPath(), "utf8")).rejects.toThrow();
  });
});

describe("browserOpeners", () => {
  const url = "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=c&state=s&scope=a%20b";

  it.each(["darwin", "win32", "linux"] as NodeJS.Platform[])("has a launcher for %s", platform => {
    expect(browserOpeners(platform, url).length).toBeGreaterThan(0);
  });

  it.each(["darwin", "linux"] as NodeJS.Platform[])("passes the URL whole on %s", platform => {
    for (const opener of browserOpeners(platform, url)) {
      expect(opener.args).toContain(url);
      expect(opener.verbatim).toBeUndefined();
    }
  });

  // explorer.exe reads its argument as a path before trying it as a URL. It opens a file
  // browser window instead once the authorize URL exceeds the Windows path limit.
  it("never asks explorer.exe to open a URL", () => {
    for (const opener of browserOpeners("win32", url)) {
      expect(opener.command).not.toMatch(/explorer/i);
    }
  });

  it("reaches the default browser through ShellExecute first on win32", () => {
    const first = browserOpeners("win32", url)[0]!;
    expect(first.command).toMatch(/rundll32/i);
    expect(first.args).toContain(url);
    expect(first.verbatim).toBeUndefined();
  });

  it("escapes every & for the cmd fallback, and quotes nothing", () => {
    const cmd = browserOpeners("win32", url).find(opener => opener.command === "cmd.exe")!;
    expect(cmd.verbatim).toBe(true);
    const target = cmd.args.at(-1)!;
    expect(target).toBe(url.replace(/&/g, "^&"));
    expect(target).not.toMatch(/&(?<!\^&)/);
    expect(target).not.toContain('"');
  });

  it("gives start its title argument before the URL", () => {
    const cmd = browserOpeners("win32", url).find(opener => opener.command === "cmd.exe")!;
    expect(cmd.args.indexOf('""')).toBeGreaterThan(cmd.args.indexOf("start"));
    expect(cmd.args.indexOf('""')).toBeLessThan(cmd.args.length - 1);
  });

  it("keeps a fallback behind the native call", () => {
    const fallback = browserOpeners("win32", url).at(-1)!;
    expect(fallback.command).toBe("cmd.exe");
    expect(browserOpeners("win32", url)).toHaveLength(2);
  });
});
