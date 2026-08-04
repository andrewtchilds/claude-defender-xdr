# Messaging query patterns

Load only the needed section. Apply the bounds and literal-handling rules from `defender-xdr-investigation` to every query.

## Table map

- `EmailEvents`: metadata, verdicts, delivery, sender, and recipient
- `EmailAttachmentInfo`: attachment names, hashes, and verdict context
- `EmailUrlInfo`: URLs contained in email
- `EmailPostDeliveryEvents`: post-delivery actions and outcomes
- `UrlClickEvents`: Safe Links and URL-click activity
- `CampaignInfo`: campaign context; may be preview
- `MessageEvents`: Teams message metadata and detections
- `MessageUrlInfo`: URLs in Teams messages
- `MessagePostDeliveryEvents`: Teams post-delivery actions
- `AlertInfo` and `AlertEvidence`: alert/entity context

Verify uncertain or tenant-specific columns with `xdr_get_schema`.

## Resolve an email

```kusto
EmailEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where NetworkMessageId == "<network-message-id>"
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress,
          SenderMailFromAddress, SenderIPv4, RecipientEmailAddress, Subject,
          DeliveryAction, DeliveryLocation, LatestDeliveryAction,
          LatestDeliveryLocation, ThreatTypes, DetectionMethods,
          AuthenticationDetails, AttachmentCount, UrlCount, ReportId
| order by Timestamp asc
| take 500
```

## Summarize recipient scope

Measure exposure before retrieving addresses.

```kusto
EmailEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where NetworkMessageId == "<network-message-id>"
| summarize Recipients=dcount(RecipientObjectId), Records=count(),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeliveryAction, DeliveryLocation, LatestDeliveryAction,
       LatestDeliveryLocation, ThreatTypes
| take 100
```

Distribution lists, shared mailboxes, and duplicate records can make recipient counts differ from people exposed.

## Inspect attachments without multiplying recipients

Aggregate attachment facts separately first. Join recipient-level rows only when the question requires them, after reducing both sides.

```kusto
EmailAttachmentInfo
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where NetworkMessageId == "<network-message-id>"
| summarize Records=count(), Recipients=dcount(RecipientObjectId)
    by NetworkMessageId, FileName, FileType, SHA256, ThreatTypes
| take 200
```

## Inspect URL presence and clicks separately

```kusto
EmailUrlInfo
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where NetworkMessageId == "<network-message-id>"
| project Timestamp, NetworkMessageId, UrlDomain, UrlLocation, ReportId
| take 500
```

```kusto
UrlClickEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where NetworkMessageId == "<network-message-id>"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough,
          IPAddress, Workload, ThreatTypes, DetectionMethods, ReportId
| order by Timestamp asc
| take 500
```

A click event does not establish credential entry, payload execution, or compromise. URL rewriting and redirect chains can defeat simple string equality; use normalized domains or inspected chain fields where appropriate.

## Verify post-delivery outcomes

```kusto
EmailPostDeliveryEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where NetworkMessageId == "<network-message-id>"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, Action, ActionType,
          ActionTrigger, ActionResult, SourceLocation, DeliveryLocation,
          ThreatTypes, ReportId
| order by Timestamp asc
| take 500
```

An action row establishes an attempted/recorded action; `ActionResult` is required to assess its outcome.

## Scope a campaign

`CampaignInfo` supplies identified campaign context; independently validate the indicators and message evidence.

```kusto
CampaignInfo
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where CampaignId == "<campaign-id>"
| summarize Messages=dcount(NetworkMessageId), Recipients=dcount(RecipientEmailAddress),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by CampaignName, CampaignType, CampaignSubtype
| take 100
```

## Investigate a Teams message

```kusto
MessageEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where TeamsMessageId == "<teams-message-id>"
| project Timestamp, LastEditedTime, TeamsMessageId, SenderObjectId, SenderType,
          IsExternalThread, ThreadSubtype, ThreatTypes, DetectionMethods,
          DeliveryAction, DeliveryLocation, SafetyTip, ReportId
| order by Timestamp asc
| take 200
```

Query `MessageUrlInfo` and `MessagePostDeliveryEvents` separately with the same `TeamsMessageId`. Preserve `ActionResult` and `LatestDeliveryLocation`; project recipient details only when necessary.
