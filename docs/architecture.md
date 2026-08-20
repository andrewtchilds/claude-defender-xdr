# Defender XDR Plugin Architecture

You ask a question in plain English. Claude writes the KQL, an MCP server on **your own
machine** runs it against Advanced Hunting through Microsoft Graph, and the rows come back for
Claude to explain. Two calls leave the machine — one to Entra for a token, one to Graph for the
query — and **every path is read-only**.

## The query path

```mermaid
flowchart TB
  subgraph machine["Your machine"]
    you["You<br/>an analyst with a question"]
    code["Claude Code<br/>4 investigation skills scope the hunt<br/>and shape the KQL that gets written"]
    mcp["defender-xdr MCP server<br/>node dist/server.js over stdio<br/>the only piece that talks to Microsoft"]
    state[("Config directory<br/>token.json · config.json — owner-only<br/>exports/ written only when you ask")]
    snapshot[("Schema snapshot<br/>64 hunting tables<br/>bundled · no network")]
    cache[("schema-cache.json<br/>columns this tenant really returns<br/>owner-only · 7-day TTL")]
  end

  subgraph cloud["Microsoft cloud"]
    entra["Microsoft Entra ID<br/>auth code + PKCE · public client, no secret<br/>delegated ThreatHunting.Read.All"]
    msgraph["Microsoft Graph<br/>POST /v1.0/security/runHuntingQuery<br/>one call per query · retries on 429 and 5xx"]
    hunting["Advanced Hunting<br/>read-only KQL over tenant telemetry<br/>your Defender role decides what you see"]
  end

  you -->|"a question in plain English"| code
  code -->|"xdr_run_query · stdio"| mcp
  mcp <-->|"reads / writes token.json"| state
  mcp -->|"xdr_get_schema — documented columns, no network"| snapshot
  mcp <-->|"tenant columns, read and written"| cache
  mcp -.->|"refresh token to access token, ~1 h, in memory"| entra
  mcp -.->|"schema probe — take 0, columns and never rows"| msgraph
  mcp -->|"query + bearer token"| msgraph
  msgraph -->|"runs the query"| hunting
  hunting -->|"result rows"| msgraph
  msgraph -->|"rows — capped at max_rows, 50 KB or less"| mcp
```

One question, one round trip. Claude never touches Microsoft directly — it calls a tool on a
local MCP server over stdio, and that server holds the token, makes the single Graph call, and
trims what comes back before it reaches the model. **Nothing in this path can change tenant
state.**

## The four tools

| Tool | What it does |
| --- | --- |
| `xdr_run_query` | Runs one read-only KQL query and returns the rows. Takes a timespan and a row limit; the configured ceiling cannot be raised per call. |
| `xdr_get_schema` | Lists, searches, or describes hunting tables. Listing and searching read local files only; describing an exact table also asks the tenant for its real columns and caches the answer. |
| `xdr_login` | Opens your browser for the Microsoft sign-in, and saves the tenant and client IDs if they were missing. Normally needed once. |
| `xdr_logout` | Deletes the sign-in cached on this machine. The browser session with Microsoft is left untouched. |

## Two views of the schema

Every table lookup answers from two sources, and says which is which.

- **The bundled snapshot** is generated from Microsoft's published documentation by
  `scripts/update-schema-snapshot.mjs`, pinned to the docs commit it read: 64 tables with prose
  descriptions, retirement notices, and doc links. It needs no network and no sign-in, and it is
  the only source that can explain what a column *means* — but it is a point in time, and the
  product moves.
- **The tenant** is asked with `TableName | take 0`: the full column list and no rows at all,
  which costs one Graph call and discloses no telemetry. Preview columns, licensing differences,
  and custom tables only exist here.

```mermaid
flowchart LR
  ask["xdr_get_schema<br/>table: DeviceInfo"] --> fresh{"cached under 7 days<br/>for this tenant?"}
  fresh -->|yes| merge
  fresh -->|"no, or refresh: true"| probe["take 0 probe<br/>silent auth only, zero rows"]
  probe -->|"columns"| write[("schema-cache.json")]
  write --> merge
  probe -.->|"signed out, or the call fails"| docs["documented columns only<br/>plus the reason it was not verified"]
  merge["merge — the tenant decides which columns exist,<br/>the documentation supplies the prose"] --> out["columns · documentedNotInTenant · liveVerification"]
  docs --> out
```

The merge is deliberately asymmetric. The tenant decides *which* columns exist, because that is
the thing it is authoritative about; the snapshot supplies the descriptions, because that is the
thing it is authoritative about. Documented columns the tenant did not return are listed under
`documentedNotInTenant` rather than dropped, since their absence is itself an answer — retired,
unlicensed, or not yet rolled out here.

Two properties matter for how it behaves in practice. The probe uses **silent authentication
only**, so a schema lookup can never pop open a browser sign-in; a signed-out user gets the
documented columns and a stated reason instead. And the cache is **keyed to the tenant**, so
switching tenants discards it rather than serving one tenant's columns for another.

## The skills layer

The tools are only half of it. The plugin also installs four investigation skills — a
cross-domain core plus endpoint, identity, and messaging branches. They are instructions, not
code: they load into Claude's context and govern *how* it hunts, not what the server will run.

- **Evidence funnel.** Frame the decision, measure cheaply, then retrieve only the smallest
  decisive records — instead of dumping raw events.
- **Cheapest table first,** then pivot on indicators — a hash, an IP, a sender — rather than
  widening the time window.
- **Read-only by contract.** The skills route every operational change into recommendations,
  because the plugin cannot make one.

## Signing in, once

```mermaid
sequenceDiagram
  autonumber
  participant Code as Claude Code
  participant MCP as MCP server, local
  participant Browser as System browser
  participant Entra as Microsoft Entra ID

  Code->>MCP: a query with no cached sign-in, or xdr_login
  MCP->>MCP: PKCE challenge, listener on 127.0.0.1, ephemeral port
  MCP->>Browser: open the authorize URL
  Browser->>Entra: your normal Microsoft sign-in, MFA included
  Entra-->>MCP: auth code returned to http://localhost
  MCP->>Entra: auth code + PKCE verifier
  Entra-->>MCP: access token, in memory
  Entra-->>MCP: refresh token, owner-only file
```

An authorization-code flow with PKCE against a loopback listener on an ephemeral port. There is
no client secret and no device code — which is why sign-in can happen inside a tool call, with
no terminal. After this, queries refresh silently until Microsoft expires or revokes the grant.

## Guardrails

- **One permission.** Delegated `ThreatHunting.Read.All`. Advanced Hunting cannot modify the
  tenant, and your own Defender role still bounds what you can see.
- **A ceiling Claude cannot raise.** `max_rows` (1000 by default) is applied as a minimum
  against whatever the model asks for, and tool output is truncated at 50 KB with a visible
  notice.
- **Bounded requests.** Four-minute wall clock, three attempts with `Retry-After` honoured,
  25 MiB response cap.
- **Local secrets stay local.** The refresh token lives in a file only your account can read;
  bearer tokens are redacted out of error text before it ever reaches the model.
- **Full result sets are opt-in.** Complete rows are written to `exports/` only when you
  explicitly ask for them.
- **No telemetry in the schema path.** The live schema probe is `take 0`, and the table name is
  matched against a bare-identifier pattern before it reaches KQL, so nothing else can be
  smuggled into the query the plugin writes for itself.

---

Drawn from the plugin source at v1.0.0 — `src/server.ts`, `src/auth.ts`, `src/graph.ts`,
`src/live-schema.ts`, and the bundled schema snapshot dated 13 April 2026 (64 tables: 42 active,
19 preview, 3 retired).
