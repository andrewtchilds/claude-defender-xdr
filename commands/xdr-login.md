---
description: Sign in to Microsoft Defender XDR in your browser
allowed-tools: mcp__plugin_defender-xdr_defender-xdr__xdr_login
---

Call the `xdr_login` tool. It opens the user's browser at the Microsoft sign-in page and
returns once they finish, so run it yourself rather than asking the user to do anything first.

If it reports that the plugin is not configured, ask the user in chat for two GUIDs — their
Entra tenant ID and the application (client) ID of a public-client app registration with
delegated `ThreatHunting.Read.All`. Neither is a secret, so it is fine to take them in chat.
Then call `xdr_login` again with `tenant_id` and `client_id`. That saves them and signs in
straight away: do not tell the user to run `/plugin configure` or to restart Claude Code.

Report the account it signs in as, and tell the user the sign-in is cached, so they will not
normally need to repeat it.
