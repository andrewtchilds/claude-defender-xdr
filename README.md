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
| `xdr_login` | Opens your browser to sign in. Optional — querying signs you in on its own. |
| `xdr_logout` | Removes the sign-in cached on this machine. |
| `xdr_run_query` | Runs a read-only KQL query against Advanced Hunting. |
| `xdr_get_schema` | Looks up hunting tables and columns. Works without signing in. |

It also installs four investigation skills — cross-domain, endpoint, identity, and messaging —
that teach Claude how to scope an investigation, pick the cheapest table, and pivot on
indicators rather than dumping raw events.

Everything is read-only. Advanced Hunting cannot modify tenant state, and the only permission
requested is the read-only `ThreatHunting.Read.All`.

[`docs/architecture.html`](docs/architecture.html) diagrams how the pieces fit together: the
query path, the sign-in flow, and the guardrails.

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

### 2. Add the marketplace

In Claude Code, add this repository as a plugin marketplace:

```
/plugin marketplace add andrewtchilds/claude-defender-xdr
```

This registers the catalog. Nothing is installed yet.

### 3. Install the plugin

Run `/plugin` to open the plugin manager, a tabbed panel you move through with **Tab**:

1. Go to the **Discover** tab and select **defender-xdr**.
2. Review the details pane. **Will install** lists every tool, skill, and MCP server the
   plugin adds, so you can see exactly what you are getting before you agree to it.
3. Press **Enter** and choose a scope — **User** for yourself across all projects,
   **Project** to share it with everyone on a repository, **Local** for this repository only.

Claude Code then offers to collect the tenant ID and application ID. Both are optional here;
whatever you leave blank, sign-in asks for and saves.

If the install summary says `Run /reload-plugins to activate.`, run that. If you would rather
not use the panel, `/plugin install defender-xdr@claude-defender-xdr` does the same thing, and
the [Claude desktop app](https://code.claude.com/docs/en/desktop#install-plugins) has its own
plugin browser.

### 4. Ask a question

There is no separate sign-in step. Ask something:

```
> which devices ran encoded powershell in the last 24 hours?
```

The first query opens your browser, you complete the normal Microsoft sign-in including MFA,
and the tab tells you when to come back. The query then runs and answers.

The sign-in is cached, so you normally do this once. Microsoft decides when it expires; when
that happens, the next query signs you in again. To sign in ahead of time, switch account, or
change tenant, run `/defender-xdr:xdr-login`.

If you skipped both IDs at install, the first query reports that the plugin is not configured.
Give Claude the two GUIDs when it asks — they are saved and applied immediately, with no
restart.

## Configuration

Settings live in the **Installed** tab of `/plugin`, or in `/plugin configure defender-xdr`
where that dialog is available. The two identifiers can be set — and changed — through sign-in
instead, which works everywhere:

```
/defender-xdr:xdr-login
```

| Setting | Default | Notes |
| --- | --- | --- |
| Entra tenant ID | — | Required. Set at install, or by sign-in. |
| Entra application (client) ID | — | Required. Set at install, or by sign-in. |
| Microsoft Graph endpoint | `https://graph.microsoft.com` | Change only for sovereign clouds. |
| Maximum rows per query | 1000 | A hard ceiling; Claude cannot raise it per query. |
| Default lookback window | `7d` | Used when your question implies no time range. |

For US Gov or China clouds, set the Graph endpoint to `https://graph.microsoft.us` or
`https://microsoftgraph.chinacloudapi.cn`. The matching Entra login host is selected
automatically, so the two can never be mismatched.

## Where things are stored

`~/.config/claude-defender-xdr/` (mode `0700`) holds:

- `config.json` (mode `0600`) — the tenant and application IDs saved by sign-in.
- `token.json` (mode `0600`) — the refresh token and the signed-in username.
- `exports/` — full result sets, written only when you explicitly ask Claude to export.

Delete the directory, or run `/defender-xdr:xdr-logout`, to remove the cached sign-in.

## Troubleshooting

**"Defender XDR is not configured"** — run `/defender-xdr:xdr-login` and give Claude the two
GUIDs when it asks. They are saved and applied immediately.

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
