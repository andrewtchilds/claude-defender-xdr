# Microsoft Defender XDR for Claude Code

Ask Claude questions about your Defender XDR data. Claude writes a KQL query, runs it through
Advanced Hunting, and explains the result.

```
> which devices ran encoded powershell in the last 24 hours?
> show me failed sign-ins for that user, grouped by country
> did anyone else receive email from that sender?
```

## What the plugin adds

| Tool | Purpose |
| --- | --- |
| `xdr_run_query` | Runs a read-only KQL query against Advanced Hunting. |
| `xdr_get_schema` | Lists tables and checks columns against your tenant. |
| `xdr_login` | Signs in or switches the tenant or account. Queries start sign-in when needed. |
| `xdr_logout` | Deletes the sign-in cached on this machine. |

The plugin requests one delegated permission, `ThreatHunting.Read.All`. Advanced Hunting is
read-only, and your Defender role still limits which data Microsoft returns.

`xdr_get_schema` reads a bundled copy of Microsoft's hunting schema. For an exact table lookup,
it can also run `TableName | take 0` against your tenant. That query returns column names and no
rows. The plugin caches those columns for one week.

`xdr_run_query` also caches columns for the tables it uses. The cache can include preview columns,
custom tables, and columns missing from Microsoft's documentation. Pass `live: false`
to use only the bundled schema or `refresh: true` to replace a cached table entry. If Defender
rejects a query, the error includes the tenant's columns for any referenced tables it could
check.

The plugin installs four investigation skills for general, endpoint, identity, and messaging
work. They tell Claude how to narrow a hunt and choose tables. They cannot change Defender data.

See [`docs/architecture.md`](https://github.com/andrewtchilds/claude-defender-xdr/blob/main/docs/architecture.md)
for the request, schema, and sign-in flows.

## Setup

### 1. Create an Entra app registration

Open [App registrations](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
in the Entra admin center and create an app with these settings:

- Supported account types: accounts in this organizational directory only
- Redirect URI type: Public client/native
- Redirect URI: `http://localhost`

Then configure the app:

1. Under **Authentication**, enable **Allow public client flows**.
2. Under **API permissions**, add the Microsoft Graph delegated permission
   `ThreatHunting.Read.All`.
3. Grant admin consent for that permission.

Copy the Directory (tenant) ID and Application (client) ID from the app's Overview page. These
IDs are not secrets. The plugin does not use a client secret.

Each user also needs a Defender XDR role that permits Advanced Hunting.

### 2. Install the plugin

Run these commands in Claude Code:

```
/plugin marketplace add andrewtchilds/claude-defender-xdr
/plugin install defender-xdr@claude-defender-xdr
```

You can also open `/plugin`, select **defender-xdr** on the **Discover** tab, and choose an install
scope:

- **User** installs it for your account.
- **Project** shares it through the repository.
- **Local** installs it only in the current repository.

Claude Code may ask for the tenant ID and application ID during installation. You can leave them
blank and supply them later through `xdr_login`. If Claude Code asks you to run
`/reload-plugins`, run it before using the tools.

### 3. Ask a question

No separate login command is required:

```
> which devices ran encoded powershell in the last 24 hours?
```

The first query asks you to sign in to Microsoft. If the MCP client can display sign-in links, it
shows one. Otherwise, the plugin opens the default browser on the same machine. Complete sign-in
and MFA, then the original query continues.

The plugin saves the refresh token for later queries. Run `/defender-xdr:xdr-login` to sign in
before a query, switch accounts, or change tenants.

If the tenant ID or application ID is missing, Claude asks for both and calls `xdr_login`. The
plugin saves them without requiring a restart.

## Configuration

| Setting | Default | Notes |
| --- | --- | --- |
| Entra tenant ID | none | Required. Set during installation or through `xdr_login`. |
| Entra application ID | none | Required. Set during installation or through `xdr_login`. |
| Microsoft Graph endpoint | `https://graph.microsoft.com` | Change this only for a sovereign cloud. |
| Maximum rows per query | 1000 | Calls can lower this limit but cannot raise it. |
| Default lookback window | `7d` | Used when the question has no time range. |

Change settings from the **Installed** tab in `/plugin`. You can also change the tenant and
application IDs with `/defender-xdr:xdr-login`.

## Local files

The plugin stores state under `~/.config/claude-defender-xdr` on macOS and Linux, or
`%APPDATA%\claude-defender-xdr` on Windows.

| Path | Contents |
| --- | --- |
| `config.json` | Tenant and application IDs saved through `xdr_login`. |
| `token.json` | Refresh token and account name. |
| `schema-cache.json` | Columns returned by your tenant. |
| `exports/` | Full query results that you explicitly asked Claude to export. |

On macOS and Linux, the plugin sets directory mode `0700` and file mode `0600`. On Windows, these
files stay inside the current user's profile and use its access controls.

Run `/defender-xdr:xdr-logout` to delete `token.json` and `schema-cache.json`. It does not sign the
browser out of Microsoft. Delete the whole directory to remove all plugin state.

## Troubleshooting

### Defender XDR is not configured

Run `/defender-xdr:xdr-login` and provide the Directory (tenant) ID and Application (client) ID
from the Entra app registration.

### Access denied with HTTP 403

Confirm that an administrator granted consent for delegated `ThreatHunting.Read.All`. Also check
that your account has a Defender XDR role that permits Advanced Hunting.

### Sign-in fails with AADSTS7000218 or a redirect error

Enable **Allow public client flows** on the app registration. Confirm that `http://localhost` is a
redirect URI under **Mobile and desktop applications**.

### The browser does not open

On Linux, install `xdg-utils`. If the MCP client displays sign-in links, use the link it provides
instead of waiting for a local browser window.

## Development

```bash
npm install
npm run verify        # typecheck, test, build, and check the plugin
npm run package       # write the plugin ZIP under build/
npm run check:package # package and validate the staged plugin
npm run schema        # replace the bundled schema snapshot
npm run schema:check  # check for Microsoft schema changes without writing
```

Runtime code uses `@modelcontextprotocol/server` v2. Protocol tests use
`@modelcontextprotocol/client` v2.

`npm run build` bundles the server into `dist/server.js`. Commit that file with every source
change. Plugin installation does not run `npm install` or build the server, so the bundle must
contain its runtime dependencies.

`npm run schema` reads Microsoft's documentation source and records the source commit in
`schema-snapshot/defender-xdr-schema.json`. Do not edit the snapshot by hand. The update script
also checks its curated retirement and errata lists against the source documents.

## Releasing

Claude Enterprise requires an administrator to upload the plugin ZIP. It does not install the
plugin from GitHub.

1. Set the same version in `.claude-plugin/plugin.json` and `package.json`.
2. Commit and push to `main`.
3. Tag the commit and push the tag:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

4. Download `defender-xdr-vX.Y.Z.zip` from the GitHub release.
5. Upload it under **Organization settings**, then **Plugins**, in Claude Enterprise.

The release workflow runs the checks, builds the ZIP, verifies the tag against the manifest
version, and publishes the archive. Run `npm run check:package` to inspect the same files under
`build/defender-xdr/` before tagging.

The ZIP contains one `defender-xdr/` directory. It includes the manifest, skills, documentation,
license, generated `package.json`, and `dist/server.js`. It does not include `node_modules` or the
schema snapshot. esbuild has already put the schema and runtime dependencies into `dist/server.js`.

The generated `package.json` contains the version and `"type": "module"`. Node needs that field to
load `dist/server.js` as ESM.

Archive digests may differ when rebuilt with another Node version because zlib output can change.
The extracted files remain the same. Release notes record the digest of the published ZIP.

## License

MIT. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
