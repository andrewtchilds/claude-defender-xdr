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

/** Prompts for tenant and client IDs only when the stored config is missing or invalid. */
async function resolveConfig(rl) {
  try {
    return await loadConfig();
  } catch (error) {
    console.error(`Defender XDR is not configured yet (${error.message}).`);
    if (!input.isTTY) {
      throw new Error(
        `Run claude-defender-xdr-login from an interactive terminal to configure it, or set CLAUDE_XDR_TENANT_ID and CLAUDE_XDR_CLIENT_ID, or write ${getConfigPath()} directly.`,
      );
    }
    const stored = await readStoredConfig();
    const ask = async (label, current) =>
      (await rl.question(`${label} [${current ?? ""}]: `)).trim() || String(current ?? "");

    const tenantId = await ask("Microsoft Entra tenant ID", stored.tenantId);
    const clientId = await ask("Entra public-client application/client ID", stored.clientId);

    const config = validateConfig({ ...DEFAULT_CONFIG, ...stored, tenantId, clientId });
    await saveStoredConfig(config);
    console.error(`Saved configuration to ${getConfigPath()}`);
    return config;
  }
}

/**
 * Creates the auth client, offering the unencrypted cache fallback only if the OS
 * credential store is unavailable and only with an explicit yes from the user.
 */
async function createAuth(rl, config) {
  try {
    return { auth: await XdrAuth.create(config), config };
  } catch (error) {
    if (!(error instanceof SecureCacheUnavailableError)) throw error;
    console.error(error.message);
    const answer = (
      await rl.question(
        "Approve an owner-only (0600) unencrypted token cache on this machine? [y/N] ",
      )
    )
      .trim()
      .toLowerCase();
    if (answer !== "y" && answer !== "yes") throw error;

    await saveStoredConfig({ ...config, allowUnencryptedTokenCache: true });
    const updated = await loadConfig();
    return { auth: await XdrAuth.create(updated), config: updated };
  }
}

const rl = createInterface({ input, output });
try {
  const { auth } = await createAuth(rl, await resolveConfig(rl));
  const result = await auth.login();
  console.log(
    `Signed in as ${result.account?.username ?? "(unknown account)"}. Token cache: ${auth.cache.security}.`,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  rl.close();
}
