# CD-021 · AS-REP Roasting After Server Compromise
| | |
|---|---|
| **Hunts for** | Kerberos TGT requests without pre-authentication (4768, PreAuthType 0) grouped by source, plus roasting tools on endpoints. Seen after the Confluence/Axis intrusion moved to a domain controller. |
| **Threat / CVE** | CVE-2026-90436 Confluence intrusion (Rapid7) |
| **MITRE ATT&CK** | T1558.004 AS-REP Roasting |
| **Category** | Credential Access |
| **First published** | 2026-11-19 (Daily Threat Review: Energy and Mining) |

## Microsoft Sentinel / Defender XDR (KQL)

```kql
// Microsoft Sentinel: domain controller security events
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4768
| extend PreAuthType = extract(@"<Data Name=""PreAuthType"">(\d+)<", 1, EventData)
| where PreAuthType == "0"
| summarize Requests=count(), Accounts=make_set(TargetUserName, 50) by IpAddress
| order by Requests desc
```

```kql
// Defender: roasting tools on endpoints
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("asreproast","GetNPUsers","kerberoast","/format:hashcat")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 CommandLine=/(asreproast|GetNPUsers|kerberoast|format:hashcat)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

## Notes

Accounts with 'Do not require Kerberos preauthentication' set will show up legitimately; fix the setting where possible.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
