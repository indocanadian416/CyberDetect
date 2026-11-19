# CD-008 · Ransomware Precursors (Shadow Copy Deletion, Log Clearing, Recovery Disable)
| | |
|---|---|
| **Hunts for** | Commands that delete shadow copies and backups, disable recovery, clear event logs or kill ESXi VMs, plus Falcon's built-in event-log-cleared and ransomware file-access events. |
| **Threat / CVE** | Akira, Qilin, INC Ransom, Shadowbyt3$ and other active groups |
| **MITRE ATT&CK** | T1490 Inhibit System Recovery; T1685.005 Clear Windows Event Logs; T1486 |
| **Category** | Impact |
| **First published** | 2026-11-11 (reused 11-12, 11-19) (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("vssadmin delete shadows","wmic shadowcopy delete","recoveryenabled no","wevtutil cl","wbadmin delete","esxcli vm process kill")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
(#event_simpleName=ProcessRollup2 CommandLine=/(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|recoveryenabled.*no|wevtutil.*\scl\s|wbadmin.*delete)/i)
OR #event_simpleName=EventLogCleared OR #event_simpleName=RansomwareFileAccessPattern
| table([@timestamp, ComputerName, #event_simpleName, CommandLine])
```

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
