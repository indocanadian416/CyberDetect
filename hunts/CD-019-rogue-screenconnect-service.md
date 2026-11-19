# CD-019 · Rogue ScreenConnect Client Installed as a Service
| | |
|---|---|
| **Hunts for** | Services named "Windows Update Agent" or containing ScreenConnect, as used in the second SCKit wave to persist a rogue remote-access client. |
| **Threat / CVE** | ScreenConnect / SCKit wave 2 (Nov 13); CVE-2026-84869 |
| **MITRE ATT&CK** | T1543.003 Windows Service; T1219 |
| **Category** | Persistence |
| **First published** | 2026-11-19 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "ServiceInstalled"
| where AdditionalFields has "Windows Update Agent" or AdditionalFields has "ScreenConnect"
| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2
| CommandLine=/Windows Update Agent/i OR (FileName=/^sc\.exe$/i CommandLine=/create.*ScreenConnect/i)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

Pair with CD-013 (ScreenConnect instance ID baseline) to find unknown client IDs.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
