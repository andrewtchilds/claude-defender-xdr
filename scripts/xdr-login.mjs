#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { SecureCacheUnavailableError } from "../dist/server/cache.js";
import { XdrAuth } from "../dist/server/auth.js";
import {
  DEFAULT_CONFIG,
  getConfigPath,
  loadConfig,
  readStoredConfig,
  saveStoredConfig,
  validateConfig,
} from "../dist/server/config.js";

const USAGE = `Usage: claude-defender-xdr-login [options]

Signs in to Microsoft Defender XDR with a delegated public-client flow. The browser
sign-in itself needs no terminal, so the whole command works non-interactively once
the tenant and client IDs are supplied.

Options:
  --tenant <guid>          Microsoft Entra tenant ID
  --client <guid>          Entra public-client application (client) ID
  --allow-unencrypted-cache
                           Pre-approve an owner-only (0600) plaintext token cache,
                           used only if the OS credential store is unavailable
  --show                   Print the current configuration and exit
  -h, --help               Show this message

IDs are also read from CLAUDE_XDR_TENANT_ID / CLAUDE_XDR_CLIENT_ID, and are saved to
${getConfigPath()} after a successful run. Client secrets are never accepted.`;

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const takeValue = name => {
      const value = argv[++i];
      if (value === undefined || value.startsWith("--")) throw new Error(`${name} requires a value`);
      return value;
    };
    switch (arg) {
      case "--tenant":
      case "--tenant-id":
        options.tenantId = takeValue(arg);
        break;
      case "--client":
      case "--client-id":
        options.clientId = takeValue(arg);
        break;
      case "--allow-unencrypted-cache":
        options.allowUnencryptedTokenCache = true;
        break;
      case "--show":
        options.show = true;
        break;
      case "-h":
      case "--help":
        options.help = true;
        break;
      default:
        throw new Error(`Unknown option ${JSON.stringify(arg)}\n\n${USAGE}`);
    }
  }
  return options;
}

/**
 * Resolves configuration from flags, environment, and the stored file, prompting only
 * when something is still missing *and* a terminal is actually attached.
 */
async function resolveConfig(options, prompt) {
  const stored = await readStoredConfig();
  const candidate = {
    ...DEFAULT_CONFIG,
    ...stored,
    ...(process.env.CLAUDE_XDR_TENANT_ID ? { tenantId: process.env.CLAUDE_XDR_TENANT_ID } : {}),
    ...(process.env.CLAUDE_XDR_CLIENT_ID ? { clientId: process.env.CLAUDE_XDR_CLIENT_ID } : {}),
    ...(options.tenantId ? { tenantId: options.tenantId } : {}),
    ...(options.clientId ? { clientId: options.clientId } : {}),
    ...(options.allowUnencryptedTokenCache ? { allowUnencryptedTokenCache: true } : {}),
  };

  try {
    return validateConfig(candidate);
  } catch (error) {
    if (!prompt) {
      throw new Error(
        `Defender XDR is not configured: ${error.message}\n\n` +
          "Supply the IDs directly (both are GUIDs from your Entra app registration):\n" +
          "  claude-defender-xdr-login --tenant <tenant-guid> --client <client-guid>\n\n" +
          `They are saved to ${getConfigPath()} and reused on later sign-ins.`,
      );
    }
    const ask = async (label, current) =>
      (await prompt(`${label} [${current ?? ""}]: `)).trim() || String(current ?? "");
    return validateConfig({
      ...candidate,
      tenantId: await ask("Microsoft Entra tenant ID", candidate.tenantId),
      clientId: await ask("Entra public-client application/client ID", candidate.clientId),
    });
  }
}

/**
 * Creates the auth client. The unencrypted cache fallback is used only when the OS
 * credential store is unavailable AND the user approved it, by flag or at a prompt.
 */
async function createAuth(config, prompt) {
  try {
    return await XdrAuth.create(config);
  } catch (error) {
    if (!(error instanceof SecureCacheUnavailableError) || config.allowUnencryptedTokenCache) throw error;
    console.error(error.message);
    if (!prompt) {
      throw new Error(
        "Re-run with --allow-unencrypted-cache to approve an owner-only (0600) plaintext " +
          "token cache, or repair the OS keychain first.",
      );
    }
    const answer = (
      await prompt("Approve an owner-only (0600) unencrypted token cache on this machine? [y/N] ")
    )
      .trim()
      .toLowerCase();
    if (answer !== "y" && answer !== "yes") throw error;
    return await XdrAuth.create({ ...config, allowUnencryptedTokenCache: true });
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(USAGE);
    return;
  }
  if (options.show) {
    const config = await loadConfig().catch(error => ({ error: error.message }));
    console.log(JSON.stringify({ configPath: getConfigPath(), ...config }, null, 2));
    return;
  }

  // Only offer prompts when a real terminal is attached. Claude Code's Bash tool and the
  // `!` prefix both run without a TTY, so prompting there would hang or fail outright.
  const rl = input.isTTY ? createInterface({ input, output }) : undefined;
  try {
    const config = await resolveConfig(options, rl && (q => rl.question(q)));
    const auth = await createAuth(config, rl && (q => rl.question(q)));

    console.error("Opening the system browser for Entra sign-in…");
    const result = await auth.login();

    // Persist only after a successful sign-in, so a bad ID is never written.
    await saveStoredConfig({ ...config, allowUnencryptedTokenCache: auth.cache.security !== "os-protected" });
    console.log(
      `Signed in as ${result.account?.username ?? "(unknown account)"}. ` +
        `Token cache: ${auth.cache.security} (${auth.cache.path}). ` +
        `Configuration saved to ${getConfigPath()}.`,
    );
  } finally {
    rl?.close();
  }
}

try {
  await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
