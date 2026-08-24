import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { createServer, type Server as HttpServer } from "node:http";
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
export const SIGN_IN_TIMEOUT_MS = 5 * 60 * 1000;

/** Refresh a little early so a token cannot expire mid-request. */
const EXPIRY_SKEW_SECONDS = 120;

export class NotSignedInError extends Error {
  constructor(detail = "No Defender XDR sign-in is cached on this machine.") {
    super(`${detail} Use the xdr_login tool to sign in.`);
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
    // A token minted for a different tenant or app is useless. Treat it as absent so the
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

export interface BrowserOpener {
  command: string;
  args: string[];
  /** cmd.exe parses its own command line, so Node must not re-quote what we wrote. */
  verbatim?: boolean;
}

/**
 * How each platform hands a URL to the default browser, most preferred first.
 *
 * Windows has no plain "open this URL" binary, so the goal is the shortest path to
 * ShellExecute, which is what resolves the `http` association to the browser the user set as
 * default. `url.dll,FileProtocolHandler` makes that call with no shell in front of it.
 *
 * `cmd /c start` reaches the same API through a shell, which is why it is only the fallback.
 * There `&` has to become `^&` or cmd reads the query string as more commands. The bare `""`
 * is the window title `start` expects first.
 *
 * `explorer.exe` is deliberately absent. It reads its argument as a filesystem path before
 * trying it as a URL, and an authorize URL runs past the Windows path limit.
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
function openSystemBrowser(url: string): void {
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

/** Public information about a pending sign-in. PKCE and OAuth secrets stay private. */
export interface SignInAttempt {
  attemptId: string;
  authorizationUrl: string;
  expiresAt: number;
}

export interface AuthenticatorOptions {
  /** Injected in tests and used by clients without URL elicitation support. */
  browserOpener?: (url: string) => void;
  /** Test seam. Production always uses the five-minute default. */
  signInTimeoutMs?: number;
}

interface PendingSignIn extends SignInAttempt {
  server: HttpServer;
  completion: Promise<string>;
  resolve: (username: string) => void;
  reject: (error: Error) => void;
  settled: boolean;
  browserOpened: boolean;
  callbackStarted: boolean;
  expiryTimer?: NodeJS.Timeout;
}

function publicAttempt(attempt: PendingSignIn): SignInAttempt {
  return {
    attemptId: attempt.attemptId,
    authorizationUrl: attempt.authorizationUrl,
    expiresAt: attempt.expiresAt,
  };
}

/** Holds access tokens and process-local interactive sign-in attempts. */
export class Authenticator {
  private accessToken?: { value: string; expiresAt: number };
  private inFlight?: Promise<string>;
  private readonly attempts = new Map<string, PendingSignIn>();
  private activeAttemptId?: string;
  private starting?: Promise<SignInAttempt>;
  private readonly browserOpener: (url: string) => void;
  private readonly signInTimeoutMs: number;

  constructor(
    private readonly config: Config,
    options: AuthenticatorOptions = {},
  ) {
    this.browserOpener = options.browserOpener ?? openSystemBrowser;
    this.signInTimeoutMs = options.signInTimeoutMs ?? SIGN_IN_TIMEOUT_MS;
  }

  /**
   * Binds the loopback listener and returns its real authorization URL without opening it.
   * Concurrent callers share the same live attempt.
   */
  async startSignIn(): Promise<SignInAttempt> {
    const active = this.activeAttemptId ? this.attempts.get(this.activeAttemptId) : undefined;
    if (active && !active.settled) return publicAttempt(active);
    if (this.starting) return await this.starting;

    const starting = this.createSignInAttempt();
    this.starting = starting;
    try {
      return await starting;
    } finally {
      if (this.starting === starting) this.starting = undefined;
    }
  }

  /** Returns an attempt while its signed request state can still be resumed. */
  signInAttempt(attemptId: string): SignInAttempt | undefined {
    const attempt = this.attempts.get(attemptId);
    return attempt ? publicAttempt(attempt) : undefined;
  }

  /** Opens the exact URL assigned to an attempt, at most once. */
  openSignInInBrowser(attemptId: string): void {
    const attempt = this.attempts.get(attemptId);
    if (!attempt) throw new Error("The Defender XDR sign-in attempt is unknown or expired.");
    if (attempt.settled) throw new Error("The Defender XDR sign-in attempt has already finished.");
    if (attempt.browserOpened) return;
    attempt.browserOpened = true;
    this.browserOpener(attempt.authorizationUrl);
  }

  /** Waits for the loopback callback and token exchange for one exact attempt. */
  async waitForSignIn(attemptId: string): Promise<string> {
    const attempt = this.attempts.get(attemptId);
    if (!attempt) throw new Error("The Defender XDR sign-in attempt is unknown or expired.");
    return await attempt.completion;
  }

  /** Stops a pending attempt, rejects its waiters, and removes it from the resumable set. */
  cancelSignIn(attemptId: string, reason = "Sign-in was cancelled."): void {
    const attempt = this.attempts.get(attemptId);
    if (!attempt) throw new Error("The Defender XDR sign-in attempt is unknown or expired.");
    if (!attempt.settled) this.finishAttempt(attempt, new Error(reason));
    if (attempt.expiryTimer) clearTimeout(attempt.expiryTimer);
    this.attempts.delete(attemptId);
  }

  async signedInAs(): Promise<string | undefined> {
    return (await readStoredToken(this.config))?.username;
  }

  /** Never opens a browser. Schema probes and tool handlers use this boundary. */
  async accessTokenSilent(): Promise<string> {
    if (this.accessToken && this.accessToken.expiresAt > Date.now()) return this.accessToken.value;
    // Collapse concurrent refreshes so parallel tool calls do not race on the same token.
    this.inFlight ??= this.refresh().finally(() => {
      this.inFlight = undefined;
    });
    return await this.inFlight;
  }

  private async createSignInAttempt(): Promise<SignInAttempt> {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const state = randomBytes(16).toString("base64url");
    let attempt: PendingSignIn | undefined;

    const server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://localhost");
      // The browser also asks for /favicon.ico. Only the callback carries a code or error.
      if (!url.searchParams.has("code") && !url.searchParams.has("error")) {
        response.writeHead(404).end();
        return;
      }
      if (!attempt || attempt.settled || attempt.callbackStarted) {
        response.writeHead(409, { "content-type": "text/html" });
        response.end(htmlPage("Sign-in already handled", "Return to your MCP client."));
        return;
      }
      attempt.callbackStarted = true;

      const returnedState = url.searchParams.get("state") ?? "";
      const expected = Buffer.from(state);
      const actual = Buffer.from(returnedState);
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        response.writeHead(400, { "content-type": "text/html" });
        response.end(htmlPage("Sign-in failed", "The response did not match this request."));
        this.finishAttempt(attempt, new Error("Sign-in response failed state validation; no token was accepted."));
        return;
      }

      const failure = url.searchParams.get("error");
      if (failure) {
        const description = url.searchParams.get("error_description") ?? failure;
        response.writeHead(400, { "content-type": "text/html" });
        response.end(htmlPage("Sign-in failed", "Return to your MCP client for details."));
        this.finishAttempt(attempt, new Error(description.split(/\r?\n/)[0]!));
        return;
      }

      response.writeHead(200, { "content-type": "text/html" });
      response.end(htmlPage("Signed in", "You can close this tab and return to your MCP client."));

      const port = (server.address() as AddressInfo).port;
      void postToken(this.config, {
        client_id: this.config.clientId,
        grant_type: "authorization_code",
        code: url.searchParams.get("code")!,
        redirect_uri: `http://localhost:${port}`,
        code_verifier: verifier,
        scope: scopeString(this.config),
      })
        .then(tokens => this.accept(tokens))
        .then(
          username => this.finishAttempt(attempt!, undefined, username),
          error => this.finishAttempt(attempt!, error as Error),
        );
    });

    // Port 0 lets the OS pick a free port. Binding to loopback keeps it off the network.
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      server.once("error", onError);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", onError);
        resolve();
      });
    }).catch(error => {
      server.close();
      throw error;
    });

    const port = (server.address() as AddressInfo).port;
    const authorizeUrl = new URL(`${this.config.loginBaseUrl}/${this.config.tenantId}/oauth2/v2.0/authorize`);
    authorizeUrl.search = new URLSearchParams({
      client_id: this.config.clientId,
      response_type: "code",
      redirect_uri: `http://localhost:${port}`,
      response_mode: "query",
      scope: scopeString(this.config),
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
      prompt: "select_account",
    }).toString();

    let resolve!: (username: string) => void;
    let reject!: (error: Error) => void;
    const completion = new Promise<string>((done, fail) => {
      resolve = done;
      reject = fail;
    });
    // A callback can fail before an MCP retry starts waiting. Keep that rejection handled while
    // preserving it for waitForSignIn(), which still receives the original error.
    void completion.catch(() => {});

    const attemptId = randomUUID();
    const expiresAt = Date.now() + this.signInTimeoutMs;
    attempt = {
      attemptId,
      authorizationUrl: authorizeUrl.toString(),
      expiresAt,
      server,
      completion,
      resolve,
      reject,
      settled: false,
      browserOpened: false,
      callbackStarted: false,
    };
    attempt.expiryTimer = setTimeout(() => {
      if (!attempt!.settled) {
        this.finishAttempt(attempt!, new Error("Timed out waiting for the browser sign-in to complete."));
      }
      this.attempts.delete(attemptId);
    }, this.signInTimeoutMs);
    attempt.expiryTimer.unref();

    server.on("error", error => this.finishAttempt(attempt!, error));
    this.attempts.set(attemptId, attempt);
    this.activeAttemptId = attemptId;
    return publicAttempt(attempt);
  }

  private finishAttempt(attempt: PendingSignIn, error?: Error, username?: string): void {
    if (attempt.settled) return;
    attempt.settled = true;
    attempt.server.close();
    if (this.activeAttemptId === attempt.attemptId) this.activeAttemptId = undefined;
    error ? attempt.reject(error) : attempt.resolve(username!);
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
      // A grant Entra itself pronounced dead is unrecoverable. Drop it so the next call
      // reports a clean sign-in request. Offline and service failures leave it in place.
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
