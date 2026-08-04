# Cross-domain query patterns

Load only the section needed. Replace every placeholder with an encoded KQL scalar, use the same UTC bounds in KQL and `xdr_run_query.timespan`, and set `max_rows` no higher than the query's final limit.

## Resolve an alert

```kusto
AlertInfo
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where AlertId == "<alert-id>"
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, AttackTechniques
| order by Timestamp asc
| take 100
```

## Pivot alert evidence

Use evidence rows to discover domain-specific stable identifiers before searching event tables.

```kusto
AlertEvidence
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where AlertId == "<alert-id>"
| project Timestamp, AlertId, EntityType, EvidenceRole, DeviceId, AccountObjectId,
          AccountUpn, SHA1, SHA256, RemoteIP, RemoteUrl, NetworkMessageId,
          ProcessCommandLine
| order by Timestamp asc
| take 500
```

## Encode untrusted literals

Construct each scalar outside the query as a quoted JSON string value, then substitute the complete encoded value, including quotes. For example, the data `example.com` becomes `"example.com"`. Inspect the resulting query to confirm that the value occupies one literal position and cannot add a pipe, operator, comment, or statement.

For a list, JSON-encode the complete list as a KQL `dynamic` value rather than concatenating source text into syntax:

```kusto
let indicators = dynamic(["example.com", "203.0.113.10"]);
DeviceNetworkEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where RemoteUrl in~ (indicators) or RemoteIP in (indicators)
| summarize Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceId, DeviceName, RemoteIP, RemoteUrl
| order by Events desc
| take 500
```

Use exact equality for stable IDs, `=~` for case-insensitive exact text, `has` for token semantics, and `contains` only for intentional substring matching.

## Validate a join

Measure each reduced side and identify whether the join key is unique enough before joining. Keep the same bounds in each source expression.

```kusto
let left = AlertEvidence
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where AlertId == "<alert-id>" and isnotempty(DeviceId)
| distinct AlertId, DeviceId;
let right = DeviceInfo
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| summarize arg_max(Timestamp, DeviceName, OSPlatform, OnboardingStatus) by DeviceId;
left
| join kind=leftouter right on DeviceId
| project AlertId, DeviceId, DeviceName, OSPlatform, OnboardingStatus
| take 500
```

If one row per key is not intended, summarize the multiplicity before accepting the joined result.
