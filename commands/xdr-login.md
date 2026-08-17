---
description: Sign in to Microsoft Defender XDR using the system browser
allowed-tools: Bash(claude-defender-xdr-login), Bash(claude-defender-xdr-login *)
---

Run `claude-defender-xdr-login` in the terminal.

The helper prompts for the tenant and public-client application IDs if they are not
configured yet, opens the system browser for Entra sign-in, validates that the returned
token is a delegated `ThreatHunting.Read.All` token for the configured tenant, and stores
it in the OS credential store. It never accepts a client secret.

Report the signed-in account and the reported token cache type back to the user. If the
command reports that secure OS storage is unavailable, explain that approving the fallback
writes tokens to an owner-only (0600) plaintext file before the user answers.
