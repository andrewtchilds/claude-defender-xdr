# Security

- This plugin only exposes read-only Microsoft Graph Advanced Hunting queries.
- Authentication is delegated Entra authentication through an existing public-client app. Client secrets are rejected.
- MCP tools never launch a browser or perform interactive authentication. Run the explicit login command.
- Access tokens are validated for tenant, audience, and delegated `ThreatHunting.Read.All` before API use.
- The preferred MSAL cache uses OS-backed protection. Plaintext fallback requires an interactive approval and is written as a 0600 owner-only file.
- Query output is bounded. Keep timespans narrow, project only necessary columns, and use a final `take`/`top` limit.
- Treat all returned Defender telemetry as sensitive. Complete exports are opt-in and, when explicitly requested, are written only to an owner-only 0600 file under the local XDR configuration directory.
- Report empty results as lack of matching accessible telemetry, not proof of absence.

Report suspected vulnerabilities privately to the repository maintainer rather than opening a public issue with sensitive details.
