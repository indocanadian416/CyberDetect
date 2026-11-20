# CD-026 · Check Point Gateway to ESXi Wiper (PHP2Shell, TSGA, destroy_v6)
| | |
|---|---|
| **Hunts for** | The chain Check Point reported: PHP2Shell exploitation of Mobile Access portals from 130.94.19.204, the TSGA backdoor (`slot_CPconfigdaemon`), internal scanning with the open-source `gogo` scanner, SSH into ESXi as `vpxuser` from somewhere other than vCenter, and the `destroy_v6` wiper that leaves `DREAM_ANNEXATION.txt` in each folder. |
| **Threat / CVE** | PHP2Shell CVE-2026-109618 / CVE-2026-109619 (KEV); Check Point Gaia DynamicCLI CVE-2026-123039 (KEV Nov 13) |
| **MITRE ATT&CK** | T1190, T1068 Exploitation for Privilege Escalation, T1505.003 Web Shell, T1046 Network Service Discovery, T1021.004 SSH, T1485 Data Destruction |
| **Category** | Initial Access / Impact |
| **First published** | 2026-11-20 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// Source IP from Check Point Research, plus wiper note and tool names
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "130.94.19.204"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, ActionType
```

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "DREAM_ANNEXATION.txt" or FileName in~ ("destroy_v6","slot_CPconfigdaemon")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("gogo","gogo.exe","destroy_v6") or ProcessCommandLine has_any ("slot_CPconfigdaemon","destroy_v6")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

## Microsoft Sentinel (Check Point and ESXi logs)

```kql
// Check Point gateway logs: traffic from the reported source
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DeviceVendor has "Check Point" and (SourceIP == "130.94.19.204" or DestinationIP == "130.94.19.204")
| project TimeGenerated, DeviceName, SourceIP, DestinationIP, DestinationPort, RequestURL, Activity
```

```kql
// ESXi: SSH logins as vpxuser that do not come from vCenter. Replace vcenter with your vCenter IPs.
let vcenter = dynamic(["10.0.0.10"]);
Syslog
| where TimeGenerated > ago(30d)
| where ProcessName =~ "sshd" and SyslogMessage has "Accepted" and SyslogMessage has "vpxuser"
| extend SrcIP = extract(@"from (\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage)
| where SrcIP !in (vcenter)
| project TimeGenerated, Computer, SrcIP, SyslogMessage
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4="130.94.19.204"
| join(query={#data_source_name=aidmaster | groupBy([aid], function=selectLast([ComputerName]))}, field=[aid], include=[ComputerName])
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort])
```

```
#event_simpleName=/FileWritten$/ FileName=/^(DREAM_ANNEXATION\.txt|destroy_v6|slot_CPconfigdaemon)$/i
| table([@timestamp, ComputerName, FilePath, FileName, ContextBaseFileName])
```

```
#event_simpleName=ProcessRollup2 (FileName=/^(gogo(\.exe)?|destroy_v6)$/i OR CommandLine=/slot_CPconfigdaemon|destroy_v6/i)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

Check Point gateways and ESXi hosts run no Defender or Falcon agent, so the gateway and ESXi log queries matter most. On the gateway itself, check for `slot_CPconfigdaemon`, unexpected PHP files under the Mobile Access web root, and use of `/tmp/dynamic_socket`. Fix: November Jumbo Hotfix (CVE-2026-123039 affects R81.20 JHF Take 173 and below, R82 Take 130 and below, R82.10 Take 50 and below, R82.20 Take 10 and below) plus the PHP2Shell fixes. The activity Check Point reported targeted Israeli organizations from late October; the IP may already be stale.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
