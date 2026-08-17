#!/usr/bin/env node
import { XdrAuth } from "../dist/server/auth.js";
import { getConfigPath, loadConfig } from "../dist/server/config.js";

async function main() {
  let config;
  try {
    config = await loadConfig();
  } catch (error) {
    throw new Error(
      `Defender XDR is not configured (${getConfigPath()}): ${error.message}\n` +
        "Nothing to sign out of. Run claude-defender-xdr-login to configure it.",
    );
  }

  const auth = await XdrAuth.create(config);
  const accounts = await auth.accounts();
  if (accounts.length === 0) {
    console.log("No Defender XDR account is cached.");
    return;
  }
  if (accounts.length > 1) {
    throw new Error(
      `Multiple accounts are cached; review and remove the token cache at ${auth.cache.path}.`,
    );
  }

  await auth.logout(accounts[0]);
  console.log(
    `Removed cached Defender XDR credentials for ${accounts[0].username || "(unknown account)"}.`,
  );
}

try {
  await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
