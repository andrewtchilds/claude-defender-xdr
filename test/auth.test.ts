import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Authenticator, browserOpeners, NotSignedInError } from "../src/auth.js";
import type { SignInHandoff, SignInPrompt } from "../src/auth.js";
import type { Config } from "../src/config.js";

const config = {
  tenantId: "31e14793-1820-4e78-bb77-295ff38db016",
  clientId: "c121ae43-424f-4d07-ba0d-c5e36b6538bb",
  graphBaseUrl: "https://graph.microsoft.com",
  loginBaseUrl: "https://login.microsoftonline.com",
  maxRows: 1000,
  defaultTimespan: "7d",
} satisfies Config;

/** Stands in for the cached-token and browser halves so no network or browser is touched. */
function authenticator(options: { signedIn: boolean }) {
  const auth = new Authenticator(config);
  let signedIn = options.signedIn;
  const silent = vi.spyOn(auth, "accessTokenSilent").mockImplementation(async () => {
    if (!signedIn) throw new NotSignedInError();
    return "access-token";
  });
  const signIn = vi.spyOn(auth, "signIn").mockImplementation(async () => {
    signedIn = true;
    return "user@example.com";
  });
  return { auth, silent, signIn };
}

describe("accessTokenReady", () => {
  it("uses the cached sign-in without opening a browser", async () => {
    const { auth, signIn } = authenticator({ signedIn: true });
    await expect(auth.accessTokenReady()).resolves.toBe("access-token");
    expect(signIn).not.toHaveBeenCalled();
  });

  it("signs in when nothing is cached, so a first query works on its own", async () => {
    const { auth, signIn } = authenticator({ signedIn: false });
    await expect(auth.accessTokenReady()).resolves.toBe("access-token");
    expect(signIn).toHaveBeenCalledTimes(1);
  });

  it("collapses concurrent callers into one browser round-trip", async () => {
    const { auth, signIn } = authenticator({ signedIn: false });
    const tokens = await Promise.all([auth.accessTokenReady(), auth.accessTokenReady(), auth.accessTokenReady()]);
    expect(tokens).toEqual(["access-token", "access-token", "access-token"]);
    expect(signIn).toHaveBeenCalledTimes(1);
  });

  it("allows a later sign-in after an earlier one failed", async () => {
    const { auth, signIn } = authenticator({ signedIn: false });
    signIn.mockRejectedValueOnce(new Error("Timed out waiting for the browser sign-in to complete."));
    await expect(auth.accessTokenReady()).rejects.toThrow(/Timed out/);
    await expect(auth.accessTokenReady()).resolves.toBe("access-token");
    expect(signIn).toHaveBeenCalledTimes(2);
  });

  it("does not sign in again for failures that a sign-in cannot fix", async () => {
    const { auth, silent, signIn } = authenticator({ signedIn: true });
    silent.mockRejectedValue(new Error("Microsoft Graph is unreachable"));
    await expect(auth.accessTokenReady()).rejects.toThrow(/unreachable/);
    expect(signIn).not.toHaveBeenCalled();
  });
});

describe("refreshing the cached sign-in", () => {
  const saved = { ...process.env };
  let directory: string;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "xdr-auth-"));
    process.env.XDG_CONFIG_HOME = directory;
  });

  afterEach(() => {
    process.env = { ...saved };
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

  // explorer.exe reads its argument as a path before trying it as a URL, and an authorize URL
  // is longer than Windows allows a path to be. It opens a file browser window instead.
  it("never asks explorer.exe to open a URL", () => {
    for (const opener of browserOpeners("win32", url)) {
      expect(opener.command).not.toMatch(/explorer/i);
    }
  });

  // ShellExecute via url.dll is the native association lookup, with no shell to escape for.
  it("reaches the default browser through ShellExecute first on win32", () => {
    const first = browserOpeners("win32", url)[0]!;
    expect(first.command).toMatch(/rundll32/i);
    expect(first.args).toContain(url);
    expect(first.verbatim).toBeUndefined();
  });

  // cmd reads a bare `&` as a command separator, which would cut the query string short.
  it("escapes every & for the cmd fallback, and quotes nothing", () => {
    const cmd = browserOpeners("win32", url).find(o => o.command === "cmd.exe")!;
    expect(cmd.verbatim).toBe(true);
    const target = cmd.args.at(-1)!;
    expect(target).toBe(url.replace(/&/g, "^&"));
    expect(target).not.toMatch(/&(?<!\^&)/);
    // Quoting would make cmd pass the carets through to the browser verbatim.
    expect(target).not.toContain('"');
  });

  // `start` reads its first quoted argument as a window title, so the title has to be there.
  it("gives start its title argument before the URL", () => {
    const cmd = browserOpeners("win32", url).find(o => o.command === "cmd.exe")!;
    expect(cmd.args.indexOf('""')).toBeGreaterThan(cmd.args.indexOf("start"));
    expect(cmd.args.indexOf('""')).toBeLessThan(cmd.args.length - 1);
  });

  it("keeps a fallback behind the native call", () => {
    const fallback = browserOpeners("win32", url).at(-1)!;
    expect(fallback.command).toBe("cmd.exe");
    expect(browserOpeners("win32", url)).toHaveLength(2);
  });
});

describe("handing the sign-in URL to the client", () => {
  /** Records what the client was asked to show, and answers the dialog on command. */
  function recordingPrompt(action: "accept" | "decline") {
    const seen: { url?: string; elicitationId?: string; settled: string[] } = { settled: [] };
    const prompt: SignInPrompt = {
      handOff(url, elicitationId): SignInHandoff {
        seen.url = url;
        seen.elicitationId = elicitationId;
        return {
          answered: Promise.resolve({ action }),
        };
      },
      settle(elicitationId) {
        seen.settled.push(elicitationId);
      },
    };
    return { prompt, seen };
  }

  it("gives the client the authorize URL instead of launching a browser", async () => {
    const { prompt, seen } = recordingPrompt("decline");
    await expect(new Authenticator(config, prompt).signIn()).rejects.toThrow(/declined/);
    expect(seen.url).toContain(`${config.loginBaseUrl}/${config.tenantId}/oauth2/v2.0/authorize`);
    expect(seen.url).toContain("code_challenge_method=S256");
    // The redirect has to name the loopback port the listener actually bound.
    expect(seen.url).toMatch(/redirect_uri=http%3A%2F%2Flocalhost%3A\d+/);
  });

  it("takes the client's dialog down once the sign-in is over", async () => {
    const { prompt, seen } = recordingPrompt("decline");
    await expect(new Authenticator(config, prompt).signIn()).rejects.toThrow(/declined/);
    expect(seen.settled).toEqual([seen.elicitationId]);
  });

  it("uses a fresh elicitation id per sign-in, so a stale dialog is never dismissed", async () => {
    const first = recordingPrompt("decline");
    const second = recordingPrompt("decline");
    await expect(new Authenticator(config, first.prompt).signIn()).rejects.toThrow(/declined/);
    await expect(new Authenticator(config, second.prompt).signIn()).rejects.toThrow(/declined/);
    expect(first.seen.elicitationId).not.toBe(second.seen.elicitationId);
  });

  it("falls back to a local browser when the client cannot show a URL", async () => {
    // handOff returning undefined is the no-elicitation client. Nothing is settled, because
    // there is no dialog to take down, and the sign-in waits on the loopback as before.
    const settled: string[] = [];
    const prompt: SignInPrompt = {
      handOff: () => undefined,
      settle: id => settled.push(id),
    };
    const auth = new Authenticator(config, prompt);
    const pending = auth.signIn();
    // Nothing resolves it here, so prove it stayed pending rather than erroring out.
    const race = await Promise.race([pending.then(() => "settled", () => "rejected"), Promise.resolve("pending")]);
    expect(race).toBe("pending");
    expect(settled).toEqual([]);
  });
});
