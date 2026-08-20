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
| `xdr_run_query` | Runs a read-only KQL query against Advanced Hunting. |
| `xdr_get_schema` | Looks up hunting tables and columns, checked against your own tenant. |
| `xdr_login` | Opens your browser to sign in. Optional, since querying signs you in on its own. |
| `xdr_logout` | Removes the sign-in cached on this machine. |

Table lookups draw on two sources. One is a snapshot of Microsoft's published schema that ships
with the plugin. The other is your tenant, which the plugin asks directly whenever you are
signed in.

Describing a table runs one zero-row query against it and caches the columns for a week.
Running a hunting query does the same for every table that query read, so the tenant's real
columns are on disk before you think to ask. That is how preview columns, custom tables, and
anything newer than the documentation show up. A column the documentation lists but your tenant
does not return is reported separately rather than dropped. Pass `live: false` to stay offline,
or `refresh: true` to ask again before the week is up.

The plugin also installs four investigation skills, one for cross-domain work and one each for
endpoint, identity, and messaging. They teach Claude to scope an investigation, pick the
cheapest table, and pivot on indicators instead of dumping raw events.

Everything is read-only. Advanced Hunting cannot modify tenant state, and the only permission
requested is the read-only `ThreatHunting.Read.All`.

[`docs/architecture.md`](https://github.com/andrewtchilds/claude-defender-xdr/blob/main/docs/architecture.md)
has diagrams of the query path, the two schema sources, and the sign-in flow.

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
Neither is a secret, and this plugin never uses a client secret.

Each person who uses the plugin also needs a Defender XDR role that permits Advanced Hunting.
The app registration grants the app's ability to ask. Their role decides what they can see.

### 2. Install the plugin

In Claude Code:

```
/plugin marketplace add andrewtchilds/claude-defender-xdr
/plugin install defender-xdr@claude-defender-xdr
```

Or run `/plugin`, pick **defender-xdr** on the **Discover** tab, and choose a scope. **User**
installs it for you, **Project** shares it with a repository, **Local** keeps it to this
repository. The details pane's **Will install** list names every tool, skill, and MCP server the
plugin adds before you agree to it.

Claude Code then offers to collect the tenant ID and application ID. Both are optional here,
and sign-in asks for whatever you leave blank. If the install summary says
`Run /reload-plugins to activate.`, run that.

### 3. Ask a question

There is no separate sign-in step. Ask something:

```
> which devices ran encoded powershell in the last 24 hours?
```

The first query opens your browser, you complete the normal Microsoft sign-in including MFA, and
the tab tells you when to come back. The query then runs and answers.

The sign-in is cached, so you normally do this once. Microsoft decides when it expires, and the
next query after that signs you in again. To sign in ahead of time, switch account, or change
tenant, run `/defender-xdr:xdr-login`.

If you skipped both IDs at install, the first query reports that the plugin is not configured.
Give Claude the two GUIDs when it asks. They are saved and applied immediately, with no restart.

## Configuration

| Setting | Default | Notes |
| --- | --- | --- |
| Entra tenant ID | none | Required. Set at install, or by sign-in. |
| Entra application (client) ID | none | Required. Set at install, or by sign-in. |
| Microsoft Graph endpoint | `https://graph.microsoft.com` | Change only for sovereign clouds. |
| Maximum rows per query | 1000 | A hard ceiling. Claude cannot raise it per query. |
| Default lookback window | `7d` | Used when your question implies no time range. |

Settings live in the **Installed** tab of `/plugin`. You can also set or change the two
identifiers by running `/defender-xdr:xdr-login`, which works everywhere.

## Where things are stored

A `claude-defender-xdr` folder in your user configuration directory holds the files below. That
is `~/.config` on macOS and Linux, `%APPDATA%` on Windows.

- `config.json` holds the tenant and application IDs saved by sign-in
- `token.json` holds the refresh token and the signed-in username
- `schema-cache.json` holds the columns your tenant reports for the tables you have queried or
  looked up
- `exports/` holds full result sets, written only when you explicitly ask Claude to export

Every file is readable only by your own account. Delete the folder, or run
`/defender-xdr:xdr-logout`, to remove the cached sign-in and the cached tenant schema.

## Troubleshooting

**"Defender XDR is not configured".** Run `/defender-xdr:xdr-login` and give Claude the two
GUIDs when it asks. They are saved and applied immediately.

**"Access denied" (403).** Admin consent was not granted for `ThreatHunting.Read.All`, or your
account lacks a Defender XDR role permitting Advanced Hunting.

**Sign-in fails with AADSTS7000218 or a redirect error.** The app registration is not a public
client. Enable **Allow public client flows** and confirm `http://localhost` is registered under
**Mobile and desktop applications**.

**The browser never opens.** The tool prints the failure. On Linux, install `xdg-utils`.

## Development

```bash
npm install
npm run verify        # typecheck, tests, build, and confirm dist/ is current
npm run package       # build the distributable plugin ZIP into build/
npm run check:package # build it, then validate the staged plugin manifest
npm run schema        # rebuild the bundled schema snapshot from Microsoft's docs
npm run schema:check  # report drift against the docs without writing
```

esbuild bundles `src/` into a single `dist/server.js`, which is committed. Claude Code installs
plugins by cloning, with no install or build step, so the server has to run straight from the
repository with no `node_modules` present. Rebuild and commit `dist/` with any change to `src/`.

The bundled schema snapshot is generated, never hand-edited. `npm run schema` reads Microsoft's
own documentation source, pins the commit it read, and rewrites
`schema-snapshot/defender-xdr-schema.json`, so the diff on that file is exactly what Microsoft
changed. Microsoft announces table retirements in prose rather than in the schema tables, so the
script carries a short curated list of them and warns when an entry stops matching the docs.

## Releasing

Releases exist so the plugin can be uploaded to a Claude Enterprise organizational marketplace,
which does not sync from GitHub. GitHub stays the source of truth; the release ZIP is just the
artifact you hand to Claude.

1. Bump `version` in `.claude-plugin/plugin.json` and in `package.json`. The two have to agree, and
   packaging fails if they do not.
2. Commit and push to `main`.
3. Tag and push the tag:

   ```bash
   git tag v1.2.2
   git push origin v1.2.2
   ```

4. The [Release workflow](.github/workflows/release.yml) typechecks, tests, rebuilds the bundle,
   validates the plugin, confirms the tag matches the manifest version, packages the ZIP, and
   creates the GitHub release. It fails the release rather than publishing a mismatch.
5. Download `defender-xdr-v1.2.2.zip` from the release page.
6. Upload that ZIP under **Organization settings → Plugins** in Claude Enterprise
   (<https://claude.ai/admin-settings/plugins>).

To see exactly what will ship before tagging, run `npm run check:package`, then inspect
`build/defender-xdr/` or load the archive with `claude --plugin-dir build/defender-xdr-v1.2.2.zip`.

The ZIP contains a single `defender-xdr/` directory holding the manifest, `skills/`, the
prebuilt `dist/server.js`, a generated `package.json`, and the docs. Claude Code accepts the
plugin either at the archive root or inside one top-level folder, and the nested layout is easier
to inspect. `schema-snapshot/` is absent on purpose: esbuild inlines that JSON into the bundle, so
it is a build input rather than a runtime file. The generated `package.json` carries nothing but
`"type": "module"` and the version, which is what tells Node to run `dist/server.js` as ESM.

## License

MIT. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
