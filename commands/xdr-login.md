---
description: Sign in to Microsoft Defender XDR in your browser
allowed-tools: mcp__plugin_defender-xdr_defender-xdr__xdr_login
---

Call the `xdr_login` tool. It opens the user's browser at the Microsoft sign-in page and
returns once they finish, so run it yourself rather than asking the user to do anything first.

Report the account it signs in as, and tell the user the sign-in is cached, so they will not
normally need to repeat it.

If it reports that the plugin is not configured, tell the user to run
`/plugin configure defender-xdr`, enter their Entra tenant ID and application (client) ID,
and then restart Claude Code so the server picks the values up.
