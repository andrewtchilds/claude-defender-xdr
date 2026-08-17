---
description: Sign in to Microsoft Defender XDR using the system browser
allowed-tools: Bash(claude-defender-xdr-login), Bash(claude-defender-xdr-login *)
---

Run `claude-defender-xdr-login` with the Bash tool. The browser sign-in does not require a
terminal, so run it yourself rather than asking the user to.

Tenant and client IDs come from the plugin's configuration prompt, so no arguments are
normally needed. It opens the system browser and waits for the user to finish signing in,
which can take a couple of minutes.

Report the signed-in account and the token cache type it prints.

If it reports that configuration is missing, tell the user to run
`/plugin configure defender-xdr` and supply their Entra tenant ID and public-client
application ID. If it reports that OS secure storage is unavailable, explain that
re-running with `--allow-unencrypted-cache` writes tokens to an owner-only (0600) plaintext
file, and let the user decide before you add that flag.
