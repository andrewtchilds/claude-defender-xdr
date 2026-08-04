#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { SecureCacheUnavailableError } from "../dist/server/cache.js";
import { XdrAuth } from "../dist/server/auth.js";
import { DEFAULT_CONFIG, getConfigPath, loadConfig, readStoredConfig, saveStoredConfig, validateConfig } from "../dist/server/config.js";

const rl = createInterface({ input, output });
try {
  const stored = await readStoredConfig();
  let config;
  try { config = await loadConfig(); } catch {
    const tenantId = (await rl.question(`Microsoft Entra tenant ID [${stored.tenantId ?? ""}]: `)).trim() || String(stored.tenantId ?? "");
    const clientId = (await rl.question(`Entra public-client application/client ID [${stored.clientId ?? ""}]: `)).trim() || String(stored.clientId ?? "");
    config = validateConfig({ ...DEFAULT_CONFIG, ...stored, tenantId, clientId });
    await saveStoredConfig(config);
    console.error(`Saved configuration to ${getConfigPath()}`);
  }
  let auth;
  try { auth = await XdrAuth.create(config); } catch (error) {
    if (!(error instanceof SecureCacheUnavailableError)) throw error;
    const answer = (await rl.question("OS secure token storage is unavailable. Approve an owner-only unencrypted token cache? [y/N] ")).trim().toLowerCase();
    if (answer !== "y" && answer !== "yes") throw error;
    await saveStoredConfig({ ...config, allowUnencryptedTokenCache: true });
    config = await loadConfig();
    auth = await XdrAuth.create(config);
  }
  const result = await auth.login();
  console.log(`Signed in as ${result.account?.username ?? "(unknown account)"}. Token cache: ${auth.cache.security}.`);
} finally { rl.close(); }
