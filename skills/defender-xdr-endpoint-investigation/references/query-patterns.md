# Endpoint query patterns

Load only the needed section. Apply the bounds and literal-handling rules from `defender-xdr-investigation` to every query.

## Table map

Verify uncertain columns with `xdr_get_schema`.

- `DeviceInfo`: identity, onboarding, exposure, and sensor/device state
- `DeviceProcessEvents`: process creation, command lines, and process relationships
- `DeviceNetworkEvents`: process-associated network activity
- `DeviceFileEvents`: file creation, modification, rename, and deletion
- `DeviceImageLoadEvents`: loaded libraries and modules
- `DeviceRegistryEvents`: registry persistence and configuration changes
- `DeviceLogonEvents`: local and remote device logons
- `DeviceEvents`: security-control and miscellaneous endpoint actions
- `DeviceNetworkInfo`: interfaces and addressing context

## Resolve a device

```kusto
DeviceInfo
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where DeviceName =~ "<device-name>"
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, OSVersion,
          OnboardingStatus, SensorHealthState, ExposureLevel
| take 20
```

## Measure process prevalence on a device

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where DeviceId == "<device-id>"
| summarize Executions=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Accounts=dcount(AccountUpn) by FileName, SHA1
| order by Executions asc
| take 200
```

## Inspect a process spine

First query the target record. Then use its process unique ID as the initiating process unique ID to retrieve direct children.

```kusto
let target = "<process-unique-id>";
DeviceProcessEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where DeviceId == "<device-id>"
| where ProcessUniqueId == target or InitiatingProcessUniqueId == target
| project Timestamp, DeviceId, DeviceName, FileName, ProcessCommandLine, SHA1,
          ProcessUniqueId, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessUniqueId, AccountUpn, ProcessCreationTime
| order by Timestamp asc
| take 500
```

A target row identifies its parent through `InitiatingProcessUniqueId`; query that ID separately if the parent record is needed. If unique-ID columns are unavailable, use `DeviceId`, PID, and creation-time constraints and label the relationship weaker.

## Pivot process-associated network activity

Confirm unique-ID availability with schema when needed. A hash can group multiple process instances, so use it only when instance identity is unavailable or prevalence is intended.

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where DeviceId == "<device-id>"
| where InitiatingProcessUniqueId == "<process-unique-id>"
| summarize Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            ActionTypes=make_set(ActionType, 20)
    by RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| order by Events desc
| take 200
```

## Scope a hash across devices

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where SHA1 == "<sha1>" or InitiatingProcessSHA1 == "<sha1>"
| summarize Executions=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceId, DeviceName, FileName
| order by Executions desc
| take 500
```

## Pivot file, registry, or logon satellites

Keep only the branch relevant to the hypothesis.

```kusto
DeviceFileEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where DeviceId == "<device-id>"
| where InitiatingProcessUniqueId == "<process-unique-id>"
| project Timestamp, ActionType, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessUniqueId, ReportId
| order by Timestamp asc
| take 500
```

```kusto
DeviceRegistryEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where DeviceId == "<device-id>"
| where InitiatingProcessUniqueId == "<process-unique-id>"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessUniqueId, ReportId
| order by Timestamp asc
| take 500
```

```kusto
DeviceLogonEvents
| where Timestamp between (datetime(<start-utc>) .. datetime(<end-utc>))
| where DeviceId == "<device-id>"
| project Timestamp, ActionType, LogonType, AccountDomain, AccountName,
          RemoteDeviceName, RemoteIP, Protocol, FailureReason, LogonId, ReportId
| order by Timestamp asc
| take 500
```
