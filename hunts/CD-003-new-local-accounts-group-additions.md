# CD-003 · New Local Accounts or Local Group Additions (RMM Takeover)
| | |
|---|---|
| **Hunts for** | Local accounts created or added to local groups on endpoints. Matches the rogue-admin pattern seen in RMM/MSP tool compromises (N-able N-central, ScreenConnect) and Barracuda follow-on activity. |
| **Threat / CVE** | N-able N-central "Able2Shell"; ScreenConnect SCKit; Barracuda ESG |
| **MITRE ATT&CK** | T1136.001 Local Account |
| **Category** | Persistence |
| **First published** | 2026-11-11 (reused 11-12) (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("UserAccountCreated", "UserAccountAddedToLocalGroup")
| project Timestamp, DeviceName, ActionType, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=/^(UserAccountCreated|UserAccountAddedToGroup)$/
| table([@timestamp, ComputerName, #event_simpleName, UserName])
| sort(@timestamp, order=desc)
```

## Notes

A hit on an endpoint managed by N-central or ScreenConnect should be treated as likely compromise: isolate the endpoint and contact the MSP.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
