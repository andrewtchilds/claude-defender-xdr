---
name: defender-xdr-endpoint-investigation
description: Investigates Defender XDR endpoint activity. Use for malware, process trees, files, network connections, registry persistence, device logons, lateral movement, hashes, IPs, or host scoping.
license: MIT
compatibility: Requires the claude-defender-xdr plugin and a Defender XDR sign-in (the first query opens the browser to sign in; `/defender-xdr:xdr-login` does it ahead of time), and access to Defender for Endpoint hunting tables.
---

# Defender XDR Endpoint Investigation

Load and apply `defender-xdr-investigation` first; its hard guardrails, evidence funnel, ledger, stop conditions, and report contract control this investigation. This skill supplies the endpoint branch.

## Endpoint invariants

- Resolve hostnames to `DeviceId`; names can be reused, renamed, or duplicated. Preserve all candidates until time and telemetry disambiguate them.
- Prefer `ProcessUniqueId` and `InitiatingProcessUniqueId`. Where unavailable, correlate PIDs only on the same device and within process creation/lifetime constraints because PIDs are reused.
- SHA1 is often more populated than SHA256 in endpoint tables. Record hash type and value; a missing hash is a coverage gap rather than a benign signal.
- Expand `AdditionalFields` only for hypothesis-relevant keys.
- Distinguish connection attempts from successful sessions using `ActionType` and corroborating telemetry.

## Endpoint branch

1. **Anchor the device.** Resolve the supplied device name, ID, IP, or alert evidence against the investigation interval. Record onboarding/sensor state where available. Continue when one or more candidate `DeviceId` values are recorded and ambiguity is explicit.

2. **Build the process spine.** Identify the target process, its parent, children, account, command line, hash, creation time, integrity/elevation, and unique IDs. Search the smallest interval that captures the chain. Continue when each relationship has direct unique-ID evidence, a time-constrained weaker correlation, or a named telemetry gap.

3. **Add hypothesis-driven satellites.** Pivot only to relevant network, file, image-load, registry, logon, or miscellaneous device events. Keep process/device keys and a tight causal interval. Continue when each suspicious behavior in the hypothesis has supporting or contradictory telemetry, or a coverage gap.

4. **Scope blast radius.** Aggregate strong hashes, destinations, accounts, or persistence artifacts across devices before retrieving records. Exclude weak strings such as a common filename unless combined with stronger context. Continue when affected device/account counts and first/last seen are known within the chosen bounds.

5. **Test prevalence and administration context.** Compare signer/company/path, historical device prevalence, software deployment, remote administration, and expected management tooling. Public IPs may represent proxies, CDNs, VPNs, or shared services; rare or unsigned binaries and LOLBin use are leads. Continue when the strongest benign alternative has been tested or its unavailable source is recorded.

6. **Return the endpoint ledger.** Emit ordered UTC events with `DeviceId`, process unique IDs, hashes, accounts, and source tables. Include clock/correlation tolerance where timestamps from different tables are linked.

Use `xdr_get_schema` when a pattern's columns are uncertain or tenant verification matters. For the table map and bounded process, network, hash, file, registry, and logon patterns, read only the relevant section of [references/query-patterns.md](references/query-patterns.md).
