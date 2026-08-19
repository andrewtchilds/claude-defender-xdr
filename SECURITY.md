# Security

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainer directly. Please
do not open a public issue for a vulnerability.

## Design

**Read-only by construction.** The only permission requested is delegated
`ThreatHunting.Read.All`. Microsoft Defender XDR Advanced Hunting is a query API: KQL hunting
queries cannot create, modify, or delete tenant state. No tool in this plugin writes to your
tenant.

**Delegated, never application, permissions.** Queries run as the signed-in user, so Defender
XDR's own role-based access control applies. The plugin cannot see data the user cannot see. No
client secret or certificate is used, accepted, or stored — the app registration is a public
client, and its application ID is not a secret.

**No shell in the sign-in path.** The authorize URL is handed to the default browser as a
single argument, never through a command interpreter, so nothing in a URL can be reinterpreted
as a command.

**Authorization code flow with PKCE.** Sign-in uses the authorization code flow with a
SHA-256 PKCE challenge against a listener bound to `127.0.0.1` on an ephemeral port. The
listener is not reachable from the network, exists only for the duration of a sign-in, and
rejects any callback whose `state` does not match the one generated for that request
(compared with a constant-time comparison).

**Token storage.** Only the refresh token is persisted, to a `claude-defender-xdr` directory
inside the user's configuration directory. On macOS and Linux that is `~/.config`, and the file
is written with mode `0600` inside a `0700` directory. On Windows it is `%APPDATA%`, which has
no POSIX modes; the file is protected there by the per-user ACL that the profile directory
already carries, and no mode is set to imply otherwise. Access tokens are held in memory for
the life of the server process and are never written to disk. A refresh token issued for a
different tenant or application ID is discarded rather than used. When Microsoft rejects a
refresh token, it is deleted immediately instead of being retried.

This is the same posture as the Azure CLI and GitHub CLI: a file readable only by your user
account. It relies on your OS account being the security boundary. If a local attacker already
has your user account, they have the token — and independently, they can run this plugin.

**Token and secret hygiene.** Tokens are never logged. Error messages from Microsoft Graph are
truncated, stripped of newlines, and scrubbed of `Bearer` values before being shown. The
plugin has no telemetry and makes no network calls other than to the configured Microsoft
login and Graph endpoints.

**Endpoint pinning.** The Graph endpoint must be one of the three official Microsoft clouds.
Its Entra login host is derived from that choice rather than configured separately, so the two
cannot be pointed at different places, and neither can be aimed at an arbitrary host.

**Bounded output.** Results are capped by a configured maximum row count that a query cannot
raise, responses over 25 MiB are refused before parsing, and tool output is truncated at 50 KB.
Full result sets are written to disk only when a user explicitly asks for an export, with the
same owner-only protection as the token file.

## Supply chain

The server is bundled into a single committed `dist/server.js` with two pure-JavaScript
dependencies: the Model Context Protocol SDK and Zod. There are no native modules, no
post-install scripts, and nothing is downloaded or installed at plugin-install time.

## What this plugin does not protect against

Query results are security data, and they flow into a Claude conversation like any other tool
output. Treat that conversation as holding the same sensitivity as the data you query, and
apply your organization's policy on what may be sent to a model provider.
