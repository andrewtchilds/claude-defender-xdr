# Identity query patterns

Load only the needed section. Apply the bounds and literal-handling rules from `defender-xdr-investigation` to every query.

## Table map

Likely sources include `EntraIdSignInEvents`, `EntraIdSpnSignInEvents`, `IdentityLogonEvents`, `IdentityDirectoryEvents`, `IdentityQueryEvents`, `IdentityInfo`, `CloudAppEvents`, `OAuthAppInfo`, `AlertInfo`, and `AlertEvidence`. `OAuthAppInfo` may be preview. Verify uncertain or tenant-specific sources with `xdr_get_schema`.

## Summarize user sign-ins

```kusto
EntraIdSignInEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where AccountObjectId == "<account-object-id>"
| summarize Attempts=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by ErrorCode, Application, IPAddress, Country, ClientAppUsed,
       AuthenticationRequirement, ConditionalAccessStatus, RiskLevelAggregated
| order by Attempts desc
| take 300
```

## Retrieve session details

```kusto
EntraIdSignInEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where AccountObjectId == "<account-object-id>"
| project Timestamp, AccountUpn, Application, ApplicationId, ResourceDisplayName,
          ErrorCode, CorrelationId, SessionId, RequestId, IPAddress, Country, City,
          DeviceName, EntraIdDeviceId, IsManaged, IsCompliant,
          AuthenticationRequirement, ConditionalAccessStatus,
          RiskLevelAggregated, RiskState, ClientAppUsed, UserAgent, ReportId
| order by Timestamp asc
| take 500
```

## Scope a possible password-spray source

A source producing failures across accounts is a lead. Inspect error-code semantics and eventual successes before assessing it.

```kusto
EntraIdSignInEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where IPAddress == "<source-ip>"
| summarize Attempts=count(), Accounts=dcount(AccountObjectId),
            SuccessfulAccounts=dcountif(AccountObjectId, ErrorCode == 0),
            ErrorCodes=make_set(ErrorCode, 20)
    by bin(Timestamp, 15m), Application
| order by Timestamp asc
| take 500
```

Retrieve successful account/session details in a separate bounded query rather than placing account lists in the initial report.

## Pivot to cloud actions

```kusto
CloudAppEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where AccountObjectId == "<account-object-id>"
| summarize Actions=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by Application, ActionType, IPAddress, CountryCode, IsAdminOperation
| order by Actions desc
| take 300
```

Administrative actions require role and business-context review before assessment.

## Inspect directory changes

Use the acting principal's stable ID and preserve both actor and target fields.

```kusto
IdentityDirectoryEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where AccountObjectId == "<account-object-id>"
| project Timestamp, ActionType, Application, AccountUpn, AccountObjectId,
          TargetAccountUpn, TargetAccountDisplayName, DeviceName, IPAddress,
          ReportId, AdditionalFields
| order by Timestamp asc
| take 500
```

Project selected `AdditionalFields` keys after inspecting a small sample and confirming that the needed semantics are absent from typed columns.

## Inspect service-principal sign-ins

```kusto
EntraIdSpnSignInEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where ServicePrincipalId == "<service-principal-id>"
| project Timestamp, ServicePrincipalName, ServicePrincipalId, IsManagedIdentity,
          Application, ApplicationId, ResourceDisplayName, ResourceId,
          ErrorCode, IPAddress, Country, CorrelationId, RequestId, ReportId
| order by Timestamp asc
| take 500
```

## Inspect OAuth application context

`OAuthAppInfo` is a context source, not proof that a consent or use was malicious.

```kusto
OAuthAppInfo
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where OAuthAppId == "<oauth-app-id>" or ServicePrincipalId == "<service-principal-id>"
| project Timestamp, OAuthAppId, ServicePrincipalId, AppName, AppStatus,
          VerifiedPublisher, PrivilegeLevel, Permissions, ConsentedUsersCount,
          IsAdminConsented, AppOrigin, LastUsedTime, ReportId
| order by Timestamp desc
| take 100
```
