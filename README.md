# Microsoft Defender XDR for Claude Code

Ask questions about your Defender XDR data in plain English. Claude writes the KQL, runs it
against Advanced Hunting, and explains what came back.

```
> which devices ran encoded powershell in the last 24 hours?
> show me failed sign-ins for that user, grouped by country
> did anyone else receive email from that sender?
```

## What it does

The plugin adds four tools to Claude Code:

| Tool | Purpose |
| --- | --- |
| `xdr_login` | Opens your browser to sign in to Microsoft. Needed once. |
| `xdr_logout` | Removes the sign-in cached on this machine. |
| `xdr_run_query` | Runs a read-only KQL query against Advanced Hunting. |
| `xdr_get_schema` | Looks up hunting tables and columns. Works without signing in. |

It also installs four investigation skills — cross-domain, endpoint, identity, and messaging —
that teach Claude how to scope an investigation, pick the cheapest table, and pivot on
indicators rather than dumping raw events.

Everything is read-only. Advanced Hunting cannot modify tenant state, and the only permission
requested is the read-only `ThreatHunting.Read.All`.

## Setup

### 1. Create an Entra app registration

In the [Entra admin center](https://entra.microsoft.com) under **App registrations → New
registration**:

- **Supported account types**: accounts in this organizational directory only
- **Redirect URI**: select **Public client/native**, and enter `http://localhost`

Then on the app you just created:

- **Authentication** → enable **Allow public client flows**
- **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**
  → add **ThreatHunting.Read.All** → then **Grant admin consent**

Copy the **Directory (tenant) ID** and **Application (client) ID** from the Overview page.
Neither is a secret. This plugin never uses a client secret.

Each person who uses the plugin also needs a Defender XDR role that permits Advanced Hunting.
The app registration grants the app's ability to ask; their role decides what they can see.

### 2. Install and configure

```bash
/plugin marketplace add <this-repo>
/plugin install defender-xdr
```

Claude Code prompts for the tenant ID and application ID as part of installing. If you skip
that, or need to change them later, run `/plugin configure defender-xdr`.

**Restart Claude Code after configuring.** The values reach the server through its environment
when it starts, so a server that is already running will not see them.

### 3. Sign in

Run `/defender-xdr:xdr-login`, or just ask a question — Claude will call `xdr_login` when it
finds no cached sign-in. Your browser opens, you complete the normal Microsoft sign-in
including MFA, and the tab tells you when to come back.

The sign-in is cached, so you normally do this once. Microsoft decides when it expires; when
that happens, sign in again.

## Configuration

All settings live in `/plugin configure defender-xdr`.

| Setting | Default | Notes |
| --- | --- | --- |
| Entra tenant ID | — | Required. |
| Entra application (client) ID | — | Required. |
| Microsoft Graph endpoint | `https://graph.microsoft.com` | Change only for sovereign clouds. |
| Maximum rows per query | 1000 | A hard ceiling; Claude cannot raise it per query. |
| Default lookback window | `7d` | Used when your question implies no time range. |

For US Gov or China clouds, set the Graph endpoint to `https://graph.microsoft.us` or
`https://microsoftgraph.chinacloudapi.cn`. The matching Entra login host is selected
automatically, so the two can never be mismatched.

## Where things are stored

`~/.config/claude-defender-xdr/` (mode `0700`) holds:

- `token.json` (mode `0600`) — the refresh token and the signed-in username.
- `exports/` — full result sets, written only when you explicitly ask Claude to export.

Delete the directory, or run `/defender-xdr:xdr-logout`, to remove the cached sign-in.

## Troubleshooting

**"Defender XDR is not configured"** — run `/plugin configure defender-xdr`, then restart
Claude Code. This message also appears when you configured the plugin but did not restart.

**"Access denied" (403)** — admin consent was not granted for `ThreatHunting.Read.All`, or
your account lacks a Defender XDR role permitting Advanced Hunting.

**Sign-in fails with AADSTS7000218 or a redirect error** — the app registration is not a
public client. Enable **Allow public client flows** and confirm `http://localhost` is
registered under **Mobile and desktop applications**.

**The browser never opens** — the tool prints the failure. On Linux, install `xdg-utils`.

## Development

```bash
npm install
npm run verify   # typecheck, tests, build, and confirm dist/ is current
```

`src/` is bundled by esbuild into a single `dist/server.js`, which is committed. Claude Code
installs plugins by cloning, with no install or build step, so the server must run straight
from the repository with no `node_modules` present. Rebuild and commit `dist/` with any
change to `src/`.

## License

MIT. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
