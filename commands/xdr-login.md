---
description: Sign in to Microsoft Defender XDR using the system browser
argument-hint: "[tenant-guid] [client-guid]"
allowed-tools: Bash(claude-defender-xdr-login), Bash(claude-defender-xdr-login *)
---

Sign the user in to Defender XDR. Arguments, if any: `$ARGUMENTS`

The browser sign-in does not require a terminal, so run this yourself with the Bash tool.

1. Check whether it is already configured: `claude-defender-xdr-login --show`.
2. If configuration is missing and the user supplied two GUIDs in `$ARGUMENTS`, run
   `claude-defender-xdr-login --tenant <first-guid> --client <second-guid>`.
   If it is already configured, just run `claude-defender-xdr-login`.
3. If configuration is missing and no GUIDs were supplied, ask the user for their Entra
   tenant ID and public-client application ID, then run the command with those. Do not
   tell the user to run it themselves — you can run it once you have the two IDs.

The command opens the system browser and waits for the user to complete Entra sign-in, so
allow it up to a few minutes. Report the signed-in account, the token cache type, and the
config path it printed.

If it reports that OS secure storage is unavailable, tell the user that re-running with
`--allow-unencrypted-cache` writes tokens to an owner-only (0600) plaintext file, and let
them decide before you add that flag. Never pass a client secret; the tool rejects them.
