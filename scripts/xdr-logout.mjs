#!/usr/bin/env node
import { XdrAuth } from "../dist/server/auth.js";
import { loadConfig } from "../dist/server/config.js";
const auth = await XdrAuth.create(await loadConfig());
const accounts = await auth.accounts();
if (!accounts.length) { console.log("No Defender XDR account is cached."); process.exit(0); }
if (accounts.length > 1) throw new Error("Multiple accounts are cached; remove the token cache after reviewing it.");
await auth.logout(accounts[0]);
console.log(`Removed cached Defender XDR credentials for ${accounts[0].username || "(unknown account)"}.`);
