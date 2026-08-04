# claude-defender-xdr

A Claude Code plugin that provides read-only Microsoft Defender XDR Advanced Hunting through MCP, plus investigation skills for endpoint, identity, messaging, and cross-domain cases.

## What changed from the pi implementation

Claude Code has no pi extension API. This package uses the Claude Code primitives that provide the same boundaries:

- **MCP stdio server**: `xdr_run_query` and `xdr_get_schema` replace pi registered tools.
- **Skills**: the investigation skills are shipped unchanged in Claude Code's supported `skills/` format.
- **Plugin commands**: `/defender-xdr:xdr-login` and `/defender-xdr:xdr-logout` invoke explicit terminal helpers for interactive authentication.
- **No automatic browser login**: the MCP server only acquires cached tokens silently. Authentication is an explicit user action.
- **Local secure cache**: MSAL uses the OS credential store where available; an unencrypted owner-only fallback requires explicit approval.

## Prerequisites

Create a Microsoft Entra app registration with:

1. **Mobile and desktop applications**, redirect URI `http://localhost`.
2. Public client flows enabled.
3. Delegated Microsoft Graph permission `ThreatHunting.Read.All`.
4. Tenant admin consent.
5. The tenant ID and client ID.

The signed-in user also needs Defender permissions for the data being queried.

## Install/develop

```bash
npm ci
npm run build
claude --plugin-dir .
```

For a packaged plugin, install the repository through Claude Code's plugin mechanism. The plugin's `.mcp.json` starts `dist/server/index.js` with the plugin root supplied by Claude Code.

## Sign in

Use `/defender-xdr:xdr-login` or run `npm run build && claude-defender-xdr-login`. The helper opens the browser only for this explicit login action. Configuration defaults to `~/.config/claude-defender-xdr/config.json`; token cache is kept in the same directory.

Environment overrides are `CLAUDE_XDR_TENANT_ID`, `CLAUDE_XDR_CLIENT_ID`, `CLAUDE_XDR_API_BASE_URL`, and `CLAUDE_XDR_AUTHORITY_HOST`.

## Safety

Queries are read-only and bounded by timespan, configured rows, response size, and MCP output limits. Tenant data is not written to disk by the MCP tool. `export_results` writes the complete API response only when the user explicitly requests it, to an owner-only file under `~/.config/claude-defender-xdr/exports/`. See [SECURITY.md](SECURITY.md).

## Skills

- `defender-xdr-investigation`
- `defender-xdr-endpoint-investigation`
- `defender-xdr-identity-investigation`
- `defender-xdr-messaging-investigation`

The skills reference `xdr_run_query` and `xdr_get_schema`, and preserve the evidence funnel, bounded KQL patterns, uncertainty handling, and reporting contract from the pi package.
