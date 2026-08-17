import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { AddressInfo } from "node:net";
import { join } from "node:path";
import { GRAPH_SCOPE, RESERVED_SCOPES, stateDir, type Config } from "./config.js";

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
  const directory = stateDir();
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700).catch(() => undefined);
  const path = tokenPath();
  await writeFile(path, `${JSON.stringify(token, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await chmod(path, 0o600).catch(() => undefined);
}

export async function clearStoredToken(): Promise<boolean> {
  try {
    await rm(tokenPath());
    return true;
  } catch {
    return false;
  }
}

/** Opens the system browser without inheriting stdio, which belongs to the MCP transport. */
function openBrowser(url: string): void {
  const [command, args] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["cmd", ["/c", "start", "", url]]
        : ["xdg-open", [url]];
  const child = spawn(command, args, { stdio: "ignore", detached: true });
  child.on("error", () => undefined);
  child.unref();
}

function tokenEndpoint(config: Config): string {
  return `${config.loginBaseUrl}/${config.tenantId}/oauth2/v2.0/token`;
}

function scopeString(config: Config): string {
  return [`${config.graphBaseUrl}/${GRAPH_SCOPE}`, ...RESERVED_SCOPES].join(" ");
}

async function postToken(config: Config, form: Record<string, string>): Promise<TokenResponse> {
  const response = await fetch(tokenEndpoint(config), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
  const body = (await response.json().catch(() => ({}))) as TokenResponse;
  if (!response.ok || !body.access_token) {
    // Entra's error_description is multi-line and carries the actionable AADSTS code.
    const detail = (body.error_description ?? body.error ?? `HTTP ${response.status}`).split(/\r?\n/)[0];
    throw new Error(detail);
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
async function authorizeInteractively(config: Config): Promise<TokenResponse> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const state = randomBytes(16).toString("base64url");

  return await new Promise<TokenResponse>((resolve, reject) => {
    let settled = false;
    const finish = (error: Error | undefined, value?: TokenResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      server.close();
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
      openBrowser(authorizeUrl.toString());
    });
  });
}

/** Holds the short-lived access token in memory so repeated queries do not re-hit Entra. */
export class Authenticator {
  private accessToken?: { value: string; expiresAt: number };
  private inFlight?: Promise<string>;

  constructor(private readonly config: Config) {}

  async signIn(): Promise<string> {
    const tokens = await authorizeInteractively(this.config);
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

  /** Never opens a browser: callers decide whether an interactive sign-in is appropriate. */
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
      // A revoked, expired, or superseded refresh token is unrecoverable: drop it so the
      // next call reports a clean "sign in again" instead of retrying a dead credential.
      await clearStoredToken();
      throw new NotSignedInError(`Your saved sign-in is no longer valid (${(error as Error).message}).`);
    }
    await this.accept(tokens);
    return this.accessToken!.value;
  }
}
