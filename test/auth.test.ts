import { describe, expect, it, vi } from "vitest";
import { Authenticator, browserOpeners, NotSignedInError } from "../src/auth.js";
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

describe("browserOpeners", () => {
  const url = "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=c&state=s&scope=a%20b";

  it.each(["darwin", "win32", "linux"] as NodeJS.Platform[])("has a launcher for %s", platform => {
    expect(browserOpeners(platform, url).length).toBeGreaterThan(0);
  });

  // The authorize URL is full of `&`. Passed to a shell it would be split into commands and
  // the browser would open a truncated URL, so it has to survive as one whole argument.
  it.each(["darwin", "win32", "linux"] as NodeJS.Platform[])("passes the URL unshelled on %s", platform => {
    for (const [command, args] of browserOpeners(platform, url)) {
      expect(command).not.toMatch(/^(cmd|sh|bash|zsh|powershell|pwsh)/i);
      expect(args).toContain(url);
    }
  });
});
