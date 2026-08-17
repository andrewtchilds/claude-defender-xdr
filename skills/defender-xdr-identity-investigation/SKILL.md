---
name: defender-xdr-identity-investigation
description: Investigates Defender XDR identity activity. Use for Entra sign-ins, MFA or Conditional Access anomalies, password spray, privilege changes, OAuth or service-principal activity, risky sessions, or account compromise.
license: MIT
compatibility: Requires the claude-defender-xdr plugin and a Defender XDR sign-in (the `xdr_login` tool, or `/defender-xdr:xdr-login`), and access to applicable identity hunting tables.
---

# Defender XDR Identity Investigation

Load and apply `defender-xdr-investigation` first; its hard guardrails, evidence funnel, ledger, stop conditions, and report contract control this investigation. This skill supplies the identity branch.

## Identity invariants

- Prefer active `EntraIdSignInEvents` and `EntraIdSpnSignInEvents` over retired `AADSignInEventsBeta` tables.
- Resolve display names and UPNs to `AccountObjectId`, and application names to stable application/service-principal IDs, before multi-table pivots.
- Separate failed authentication, successful authentication, token/session activity, and post-authentication actions.
- MFA required is distinct from MFA completed. Sign-in success is distinct from Conditional Access success; inspect the corresponding fields per event.
- Establish a bounded baseline before describing a country, IP, client, device, application, or action as unusual.

## Fast path: recent interactive sign-ins

`EntraIdSignInEvents.LogonType` stores a JSON-like string. Interactive and non-interactive values are commonly `["interactiveUser"]` and `["nonInteractiveUser"]`. Use exact equality:

```kusto
EntraIdSignInEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where AccountUpn =~ "<user-upn>"
| where LogonType == '["interactiveUser"]'
| project Timestamp, AccountUpn, AccountObjectId, Application,
          ResourceDisplayName, ErrorCode, IPAddress, Country, State, City,
          DeviceName, EntraIdDeviceId, OSPlatform, DeviceTrustType,
          IsManaged, IsCompliant, Browser, ClientAppUsed,
          AuthenticationRequirement, ConditionalAccessStatus,
          RiskLevelAggregated, RiskState, CorrelationId, SessionId, ReportId
| top <count> by Timestamp desc
```

Run with a matching narrow `timespan` and `max_rows=<count>`. Retain failures unless the question is explicitly limited to success. `ErrorCode == 0` generally indicates success; verify semantics relevant to the case. Repeated rows with one `SessionId` need not represent separate authentication ceremonies.

## Identity branch

1. **Resolve the principal.** Establish tenant context, stable account/application IDs, and enabled/role/risk context where relevant. Continue when every supplied name maps to candidate IDs or remains an explicit ambiguity.
2. **Characterize authentication.** Count success and failure by time bucket, source, application, client, and error code. Compare the case interval to a longer bounded baseline. Continue when the suspicious session and its degree of novelty are measurable.
3. **Inspect controls and session continuity.** Review authentication requirement, Conditional Access, risk, device trust/compliance, correlation, request, report, and session IDs. Continue when claims about MFA, policy, and session linkage are field-supported or explicitly unresolved.
4. **Test impact.** Pivot suspicious successful sessions to directory and cloud-application actions. For spray, scope one source across accounts and test for eventual successes. For service principals/OAuth, inspect stable IDs, consent/privilege context, and subsequent use. Continue when post-authentication impact is evidenced or bounded by a coverage gap.
5. **Return the identity ledger.** Preserve relevant account, application, session, correlation, request, and report IDs in an ordered UTC timeline.

Use `xdr_get_schema` for patterns outside the bundled reference, preview sources, or tenant drift. For aggregation, spray, cloud-action, directory, OAuth, and service-principal patterns, read only the relevant section of [references/query-patterns.md](references/query-patterns.md).
