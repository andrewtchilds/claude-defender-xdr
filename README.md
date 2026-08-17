# claude-defender-xdr

A Claude Code plugin for read-only Microsoft Defender XDR Advanced Hunting: two MCP tools
plus investigation skills for endpoint, identity, messaging, and cross-domain cases.

## What it provides

| Component | Name | Purpose |
| --- | --- | --- |
| MCP tool | `xdr_run_query` | Bounded, read-only KQL against Advanced Hunting via Microsoft Graph |
| MCP tool | `xdr_get_schema` | List, search, or describe hunting tables from a bundled schema snapshot, optionally verified live against the tenant |
| Command | `/defender-xdr:xdr-login` | Explicit interactive Entra sign-in |
| Command | `/defender-xdr:xdr-logout` | Remove the cached account |
| Skills | `defender-xdr-investigation` and the endpoint, identity, and messaging branches | Evidence funnel, bounded KQL patterns, uncertainty handling, and reporting contract |

Design boundaries:

- **Read-only.** Only `POST /v1.0/security/runHuntingQuery`, which cannot change tenant state.
- **No implicit authentication.** MCP tools acquire cached tokens silently and never open a
  browser. Sign-in is always an explicit user action.
- **No client secrets.** Delegated public-client flow only; a `clientSecret` in the config
  file is rejected outright.
- **Secure token storage.** MSAL uses the OS credential store. An owner-only (0600)
  plaintext fallback requires interactive approval.

## Prerequisites

Node.js 20 or newer, and a Microsoft Entra app registration with:

1. A **Mobile and desktop applications** platform with redirect URI `http://localhost`.
2. Public client flows enabled.
3. The delegated Microsoft Graph permission `ThreatHunting.Read.All`.
4. Tenant admin consent.

The signed-in user also needs Defender RBAC covering the data being queried.

## Install

This plugin has a native dependency (`keytar`, via `@azure/msal-node-extensions`) for the
OS credential store, so it needs an `npm install` after the plugin files are in place.
Claude Code installs plugins by cloning without running a build, so do this once:

```bash
git clone <repository-url> claude-defender-xdr
cd claude-defender-xdr
npm ci
```

On Linux, `keytar` also needs `libsecret` (`sudo apt-get install libsecret-1-dev`).

Then load it:

```bash
claude --plugin-dir /path/to/claude-defender-xdr
```

Or add the repository through a [plugin marketplace](https://code.claude.com/docs/en/plugin-marketplaces)
and run `npm ci` inside the installed plugin directory.

`dist/` is committed, so no build step is required to run the plugin. Rebuild it whenever
you change `server/`; `npm run verify` fails if the two drift apart.

> If `npm ci` has not been run, `xdr_run_query` and sign-in will fail. `xdr_get_schema`
> still works offline from the bundled snapshot.

## Configure and sign in

Claude Code prompts for the plugin's settings when it is enabled, via the `userConfig`
declaration in `plugin.json`. Re-open that dialog any time with:

```
/plugin configure defender-xdr
```

| Option | Required | Default |
| --- | --- | --- |
| Entra tenant ID | yes | — |
| Entra application (client) ID | yes | — |
| Microsoft Graph endpoint | no | `https://graph.microsoft.com` |
| Maximum rows per query | no | `1000` |
| Default lookback window | no | `7d` |
| Allow unencrypted token cache | no | `false` |

You can also set them at install time:

```bash
claude plugin install defender-xdr@<marketplace> \
  --config tenant_id=<guid> --config client_id=<guid>
```

Then sign in with `/defender-xdr:xdr-login`. It opens the system browser and needs no
arguments — it reads the same settings you entered above.

Selecting a sovereign cloud (`https://graph.microsoft.us` or
`https://microsoftgraph.chinacloudapi.cn`) derives the matching Entra authority
automatically, so the two cannot end up mismatched.

**Standalone use**, outside the plugin: settings fall back to
`~/.config/claude-defender-xdr/config.json` (or `$XDG_CONFIG_HOME`), and
`claude-defender-xdr-login --tenant <guid> --client <guid>` writes that file. The
`CLAUDE_XDR_TENANT_ID`, `CLAUDE_XDR_CLIENT_ID`, `CLAUDE_XDR_API_BASE_URL`, and
`CLAUDE_XDR_AUTHORITY_HOST` variables override everything else. Run
`claude-defender-xdr-login --show` to see what the resolved configuration is.

## Safety

Queries are bounded by timespan, configured row limit, a 25 MiB response ceiling, and a
50 KiB tool-output limit. Truncated output is marked and is deliberately not valid JSON, so
a prefix cannot be mistaken for a complete result set.

Tenant data is not written to disk unless the user explicitly sets `export_results=true`,
which writes the full response to an owner-only file under
`~/.config/claude-defender-xdr/exports/`. See [SECURITY.md](SECURITY.md).

## Develop

```bash
npm ci
npm run verify   # typecheck, tests, rebuild, dist freshness, plugin manifest validation
```

Layout: `server/` is the MCP server (TypeScript, compiled to `dist/`), `bin/` holds the
PATH shims Claude Code exposes, `scripts/` the login/logout helpers, `skills/` the
investigation skills, and `schema-snapshot/` the bundled Advanced Hunting schema.
