import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { readFile, rm } from "node:fs/promises";
import { AddressInfo } from "node:net";
import { join } from "node:path";
import {
  GRAPH_SCOPE,
  makeOwnerOnlyDir,
  RESERVED_SCOPES,
  stateDir,
  writeOwnerOnlyFile,
  type Config,
} from "./config.js";

/** How long the loopback listener waits for the user to finish signing in. */
const SIGN_IN_TIMEOUT_MS = 5 * 60 * 1000;

/** Refresh a little early so a token cannot expire mid-request. */
const EXPIRY_SKEW_SECONDS = 120;

export class NotSignedInError extends Error {
  constructor(detail = "No Defender XDR sign-in is cached on this machine.") {
    super(`${detail} Use the xdr_login tool to sign in; it opens your browser.`);
    this.name = "NotSignedInError";
  }
}

/**
 * OAuth error codes with which Entra declares the grant itself dead: revoked, expired,
 * superseded, or requiring fresh interaction. Only these make the stored refresh token
 * worthless. Anything else the endpoint may say is a failure to ask, not a dead grant.
 */
const GRANT_REJECTED = new Set(["invalid_grant", "interaction_required"]);

/** A token request Entra answered with an error, as opposed to one that never got through. */
class TokenRequestError extends Error {
  constructor(
    message: string,
    private readonly oauthError: string | undefined,
  ) {
    super(message);
    this.name = "TokenRequestError";
  }

  get grantRejected(): boolean {
    return this.oauthError !== undefined && GRANT_REJECTED.has(this.oauthError);
  }
}

interface StoredToken {
  refreshToken: string;
  username: string;
  tenantId: string;
  clientId: string;
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  id_token?: string;
  error?: string;
  error_description?: string;
}

function tokenPath(): string {
  return join(stateDir(), "token.json");
}

/** Reads the `preferred_username` claim for display only; the signature is Entra's concern. */
function usernameFromIdToken(idToken: string | undefined): string {
  const payload = idToken?.split(".")[1];
  if (!payload) return "unknown account";
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString()) as Record<string, unknown>;
    const name = claims.preferred_username ?? claims.upn ?? claims.email;
    return typeof name === "string" ? name : "unknown account";
  } catch {
    return "unknown account";
  }
}

async function readStoredToken(config: Config): Promise<StoredToken | undefined> {
  let raw: string;
  try {
    raw = await readFile(tokenPath(), "utf8");
  } catch {
    return undefined;
  }
  try {
    const stored = JSON.parse(raw) as StoredToken;
    if (typeof stored?.refreshToken !== "string" || !stored.refreshToken) return undefined;
    // A token minted for a different tenant or app is useless; treat it as absent so the
    // user is asked to sign in again rather than shown a confusing Entra rejection.
    if (stored.tenantId !== config.tenantId || stored.clientId !== config.clientId) return undefined;
    return stored;
  } catch {
    return undefined;
  }
}

async function writeStoredToken(token: StoredToken): Promise<void> {
  await makeOwnerOnlyDir(stateDir());
  await writeOwnerOnlyFile(tokenPath(), `${JSON.stringify(token, null, 2)}\n`);
}

export async function clearStoredToken(): Promise<boolean> {
  try {
    await rm(tokenPath());
    return true;
  } catch {
    return false;
  }
}

/**
 * How a sign-in URL reaches the person signing in.
 *
 * A client that supports URL elicitation opens the URL itself, which is the whole point: this
 * process then launches nothing, so there is no platform launcher to get wrong and no
 * `rundll32` or `powershell` child process for an EDR to flag. The launcher below is only
 * for clients that cannot show a URL.
 */
export interface SignInHandoff {
  /** Resolves when the person answers the client's dialog. Rejects if it cannot show one. */
  readonly answered: Promise<{ action: string }>;
}

export interface SignInPrompt {
  /** Returns undefined when the client has no way to put a URL in front of the user. */
  handOff(url: string, elicitationId: string): SignInHandoff | undefined;
  /** Tells the client the sign-in is over, so it can take its dialog down. */
  settle(elicitationId: string): void;
}

export interface BrowserOpener {
  command: string;
  args: string[];
  /** cmd.exe parses its own command line, so Node must not re-quote what we wrote. */
  verbatim?: boolean;
}

/**
 * How each platform hands a URL to the default browser, most preferred first. This runs only
 * when the client cannot show a URL itself; see SignInPrompt.
 *
 * Windows has no plain "open this URL" binary, so the goal is the shortest path to
 * ShellExecute, which is what resolves the `http` association to whatever browser the user
 * set as default. `url.dll,FileProtocolHandler` is that call with no shell in front of it,
 * and rundll32 reads everything after the comma and space as one argument, so a query string
 * full of `&` needs no escaping.
 *
 * `cmd /c start` reaches the same API through a shell, which is why it is only the fallback.
 * There `&` has to become `^&` or cmd reads the query string as more commands, and the URL
 * stays unquoted because `^` is literal inside double quotes and the carets would reach the
 * browser. The bare `""` is the window title `start` expects first, and without it start
 * reads the URL as a title and opens nothing.
 *
 * `explorer.exe` is deliberately absent. It reads its argument as a filesystem path before
 * trying it as a URL, and an authorize URL runs past 400 characters, well beyond the
 * 260-character path limit. Explorer gives up and opens a file browser window instead.
 */
export function browserOpeners(platform: NodeJS.Platform, url: string): BrowserOpener[] {
  switch (platform) {
    case "darwin":
      return [{ command: "open", args: [url] }];
    case "win32":
      return [
        { command: "rundll32.exe", args: ["url.dll,FileProtocolHandler", url] },
        {
          command: "cmd.exe",
          args: ["/c", "start", '""', "/b", url.replace(/&/g, "^&")],
          verbatim: true,
        },
      ];
    default:
      return [{ command: "xdg-open", args: [url] }];
  }
}

/** Opens the system browser without inheriting stdio, which belongs to the MCP transport. */
function openBrowser(url: string): void {
  const openers = browserOpeners(process.platform, url);
  const attempt = (index: number): void => {
    const opener = openers[index];
    if (!opener) return;
    const child = spawn(opener.command, opener.args, {
      stdio: "ignore",
      detached: true,
      windowsHide: true,
      windowsVerbatimArguments: opener.verbatim,
    });
    // A launcher that is not installed fails with ENOENT, and one that ran but could not
    // reach a browser exits non-zero. Either way the next opener gets a turn.
    child.on("error", () => attempt(index + 1));
    child.on("exit", code => {
      if (code !== 0) attempt(index + 1);
    });
    child.unref();
  };
  attempt(0);
}

function tokenEndpoint(config: Config): string {
  return `${config.loginBaseUrl}/${config.tenantId}/oauth2/v2.0/token`;
}

function scopeString(config: Config): string {
  return [`${config.graphBaseUrl}/${GRAPH_SCOPE}`, ...RESERVED_SCOPES].join(" ");
}

async function postToken(config: Config, form: Record<string, string>): Promise<TokenResponse> {
  let response: Response;
  try {
    response = await fetch(tokenEndpoint(config), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form).toString(),
    });
  } catch (error) {
    // The request never reached Entra, so this says nothing about the grant it carried.
    throw new Error(`Could not reach Microsoft Entra: ${(error as Error).message}`);
  }
  const body = (await response.json().catch(() => ({}))) as TokenResponse;
  if (!response.ok || !body.access_token) {
    // Entra's error_description is multi-line and carries the actionable AADSTS code.
    const detail = (body.error_description ?? body.error ?? `HTTP ${response.status}`).split(/\r?\n/)[0]!;
    throw new TokenRequestError(detail, typeof body.error === "string" ? body.error : undefined);
  }
  return body;
}

function htmlPage(title: string, message: string): string {
  return `<!doctype html><meta charset="utf-8"><title>${title}</title>
<body style="font-family:system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;color:#222E65">
<div style="text-align:center"><h1 style="font-size:1.25rem">${title}</h1><p>${message}</p></div>`;
}

/**
 * Runs the authorization-code flow with PKCE against a loopback listener.
 *
 * Entra treats `http://localhost` as a special public-client redirect where any port
 * matches, so this binds an ephemeral port rather than requiring a fixed one to be
 * registered. Nothing here needs a terminal, which is why it can run inside an MCP tool.
 */
async function authorizeInteractively(config: Config, prompt?: SignInPrompt): Promise<TokenResponse> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const state = randomBytes(16).toString("base64url");

  return await new Promise<TokenResponse>((resolve, reject) => {
    const elicitationId = randomUUID();
    let handedOff = false;
    let settled = false;
    const finish = (error: Error | undefined, value?: TokenResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      server.close();
      // The client cannot see the loopback callback, so its dialog stays up until told.
      if (handedOff) prompt?.settle(elicitationId);
      error ? reject(error) : resolve(value!);
    };

    const timer = setTimeout(
      () => finish(new Error("Timed out waiting for the browser sign-in to complete.")),
      SIGN_IN_TIMEOUT_MS,
    );

    const server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://localhost");
      // The browser also asks for /favicon.ico; only the callback carries a code or error.
      if (!url.searchParams.has("code") && !url.searchParams.has("error")) {
        response.writeHead(404).end();
        return;
      }

      const returnedState = url.searchParams.get("state") ?? "";
      const expected = Buffer.from(state);
      const actual = Buffer.from(returnedState);
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        response.writeHead(400, { "content-type": "text/html" });
        response.end(htmlPage("Sign-in failed", "The response did not match this request."));
        finish(new Error("Sign-in response failed state validation; no token was accepted."));
        return;
      }

      const failure = url.searchParams.get("error");
      if (failure) {
        const description = url.searchParams.get("error_description") ?? failure;
        response.writeHead(400, { "content-type": "text/html" });
        response.end(htmlPage("Sign-in failed", "Return to Claude Code for details."));
        finish(new Error(description.split(/\r?\n/)[0]!));
        return;
      }

      response.writeHead(200, { "content-type": "text/html" });
      response.end(htmlPage("Signed in", "You can close this tab and return to Claude Code."));

      const port = (server.address() as AddressInfo).port;
      postToken(config, {
        client_id: config.clientId,
        grant_type: "authorization_code",
        code: url.searchParams.get("code")!,
        redirect_uri: `http://localhost:${port}`,
        code_verifier: verifier,
        scope: scopeString(config),
      }).then(
        tokens => finish(undefined, tokens),
        error => finish(error as Error),
      );
    });

    server.on("error", error => finish(error as Error));

    // Port 0 lets the OS pick a free port; binding to loopback keeps it off the network.
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      const authorizeUrl = new URL(`${config.loginBaseUrl}/${config.tenantId}/oauth2/v2.0/authorize`);
      authorizeUrl.search = new URLSearchParams({
        client_id: config.clientId,
        response_type: "code",
        redirect_uri: `http://localhost:${port}`,
        response_mode: "query",
        scope: scopeString(config),
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
        prompt: "select_account",
      }).toString();
      const url = authorizeUrl.toString();
      const handoff = prompt?.handOff(url, elicitationId);
      if (!handoff) {
        openBrowser(url);
        return;
      }
      handedOff = true;
      handoff.answered.then(
        result => {
          // Anything but acceptance is the person calling the sign-in off. Arriving after a
          // successful callback is normal, and finish() ignores it.
          if (result.action !== "accept") finish(new Error("Sign-in was declined."));
        },
        () => {
          // The client took the request and could not show it after all. Open one here.
          handedOff = false;
          openBrowser(url);
        },
      );
    });
  });
}

/** Holds the short-lived access token in memory so repeated queries do not re-hit Entra. */
export class Authenticator {
  private accessToken?: { value: string; expiresAt: number };
  private inFlight?: Promise<string>;
  private signingIn?: Promise<string>;

  constructor(
    private readonly config: Config,
    private readonly prompt?: SignInPrompt,
  ) {}

  async signIn(): Promise<string> {
    const tokens = await authorizeInteractively(this.config, this.prompt);
    return await this.accept(tokens);
  }

  async signedInAs(): Promise<string | undefined> {
    return (await readStoredToken(this.config))?.username;
  }

  private async accept(tokens: TokenResponse): Promise<string> {
    const username = usernameFromIdToken(tokens.id_token);
    if (tokens.refresh_token) {
      await writeStoredToken({
        refreshToken: tokens.refresh_token,
        username,
        tenantId: this.config.tenantId,
        clientId: this.config.clientId,
      });
    }
    this.accessToken = {
      value: tokens.access_token!,
      expiresAt: Date.now() + Math.max(0, (tokens.expires_in ?? 3600) - EXPIRY_SKEW_SECONDS) * 1000,
    };
    return username;
  }

  /**
   * Returns a usable access token, opening the browser to sign in if nothing is cached.
   *
   * Letting the first query sign itself in is what makes a fresh install work without the
   * caller having to know that `xdr_login` exists. Concurrent callers share one browser
   * round-trip; without the guard, parallel tool calls would each open a window.
   */
  async accessTokenReady(): Promise<string> {
    try {
      return await this.accessTokenSilent();
    } catch (error) {
      if (!(error instanceof NotSignedInError)) throw error;
      this.signingIn ??= this.signIn().finally(() => {
        this.signingIn = undefined;
      });
      await this.signingIn;
      // accept() cached the new access token in memory, so this resolves without a refresh.
      return await this.accessTokenSilent();
    }
  }

  /** Never opens a browser: callers that must not interrupt the user use this instead. */
  async accessTokenSilent(): Promise<string> {
    if (this.accessToken && this.accessToken.expiresAt > Date.now()) return this.accessToken.value;
    // Collapse concurrent refreshes so parallel tool calls do not race on the same token.
    this.inFlight ??= this.refresh().finally(() => {
      this.inFlight = undefined;
    });
    return await this.inFlight;
  }

  private async refresh(): Promise<string> {
    const stored = await readStoredToken(this.config);
    if (!stored) throw new NotSignedInError();

    let tokens: TokenResponse;
    try {
      tokens = await postToken(this.config, {
        client_id: this.config.clientId,
        grant_type: "refresh_token",
        refresh_token: stored.refreshToken,
        scope: scopeString(this.config),
      });
    } catch (error) {
      // A grant Entra itself pronounced dead is unrecoverable: drop it so the next call
      // reports a clean "sign in again" instead of retrying a dead credential. An offline
      // moment or a 5xx from the token endpoint says nothing about the grant, so the token
      // stays for the retry that would have succeeded.
      if (error instanceof TokenRequestError && error.grantRejected) {
        await clearStoredToken();
        throw new NotSignedInError(`Your saved sign-in is no longer valid (${error.message}).`);
      }
      throw error;
    }
    await this.accept(tokens);
    return this.accessToken!.value;
  }
}
