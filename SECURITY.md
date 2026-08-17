# Security

## Design boundaries

- **Read-only by construction.** The only API call is `POST /v1.0/security/runHuntingQuery`,
  which cannot write or change tenant state. Operational actions appear in reports as
  recommendations for authorized personnel, never as tool calls.
- **Delegated public-client authentication only.** Client secrets are rejected during config
  validation. The redirect URI is pinned to `http://localhost`, and `apiBaseUrl` is pinned to
  an official Microsoft Graph cloud with a matching Entra authority.
- **No implicit authentication.** MCP tools only acquire cached tokens silently and surface
  `AuthenticationRequiredError` otherwise. They never open a browser. Interactive sign-in
  happens only through the explicit `/defender-xdr:xdr-login` command.
- **Token validation before use.** Every acquired access token is checked for audience,
  tenant, and the delegated `ThreatHunting.Read.All` scope. This is a fail-fast
  configuration check, not a substitute for Graph's own signature validation.

## Secrets and storage

- Tokens are stored via the OS credential store (Keychain, DPAPI, or Secret Service).
- The plaintext fallback requires interactive approval at login time and is written as a
  0600 owner-only file in a 0700 directory.
- The config file is written atomically as 0600 and never contains a secret.
- Error messages passing through the auth and HTTP layers are scrubbed of bearer tokens and
  token-shaped values, and MSAL's own logging is disabled because its callbacks can carry
  tokens and account identifiers.

## Data handling

- Query output is bounded by timespan, configured row limit, a 25 MiB response ceiling, and
  a 50 KiB tool-output limit. Truncated output is explicitly marked and left as invalid JSON
  so a prefix cannot be mistaken for a complete result set.
- Tenant telemetry is not written to disk by default. `export_results=true` writes the full
  response to a 0600 file under `~/.config/claude-defender-xdr/exports/`, and the skills
  instruct Claude to set it only after the user explicitly asks for a local export.
- Treat all returned Defender telemetry as sensitive. Keep timespans narrow, project only
  necessary columns, and end queries with a `take`/`top` limit.
- Report empty results as a lack of matching accessible telemetry, not as proof of absence.

## Known considerations

- `@azure/msal-node-extensions` depends on `keytar`, a native module whose upstream project
  is archived. It is the reason this plugin needs `npm ci` after installation. Track it when
  auditing dependencies.
- KQL is assembled by the model. The skills require every untrusted scalar (usernames,
  hostnames, URLs, message IDs) to be encoded as a valid KQL string literal and the finished
  query inspected before execution. The Advanced Hunting API is read-only, which bounds the
  impact of a malformed or injected query to over-broad reads.

## Reporting

Report suspected vulnerabilities privately to the repository maintainer rather than opening
a public issue with sensitive details.
