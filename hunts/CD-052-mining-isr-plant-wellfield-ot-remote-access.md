# CD-052 · Mining / ISR Plant and Wellfield Control Networks: Unexpected Remote Access (Peninsula Energy, Lance)
| | |
|---|---|
| **Hunts for** | Connections from outside the plant / wellfield OT ranges into them on remote-access and industrial ports. Also remote-access tools (AnyDesk, TeamViewer, RustDesk, ScreenConnect, VNC, ngrok, Chisel, plink) running on HMI, SCADA and engineering workstations, new interactive or RDP logons to those hosts, and changes to PLC project / HMI configuration files. |
| **Threat / CVE** | Peninsula Energy (ASX: PEN) cyber incident. On Nov 20, 2026 it hit the plant and wellfield operating and control systems at the Lance in-situ recovery uranium project, Crook County, Wyoming. Operations are suspended until recovery and verification are complete. Corporate and admin systems were not affected. Shares were halted from Nov 23. No CVE, actor or IOCs published. Context: Dragos counted 19 ransomware attacks on mining organisations in Q3 2026, and the Canadian Cyber Centre warns of AI-assisted attacks on internet-exposed PLCs (energy, water). |
| **MITRE ATT&CK** | ICS: T0822 External Remote Services, T0886 Remote Services, T0883 Internet Accessible Device, T0826 Loss of Availability. Enterprise: T1219 Remote Access Software, T1133 External Remote Services |
| **Category** | OT / ICS |
| **First published** | 2026-11-25 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// 1. Connections into OT ranges from outside them on remote-access / industrial ports
let otRanges = dynamic(["<plant / wellfield / SCADA CIDRs>"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ipv4_is_in_any_range(RemoteIP, otRanges) and not(ipv4_is_in_any_range(LocalIP, otRanges))
| where RemotePort in (3389, 5900, 5938, 22, 23, 445, 502, 102, 44818, 20000, 2404, 4840, 1911, 47808)
| summarize Conns=count(), Ports=make_set(RemotePort), First=min(Timestamp), Last=max(Timestamp)
          by DeviceName, LocalIP, RemoteIP, InitiatingProcessFileName, InitiatingProcessAccountName
| order by First desc
```

```kql
// 2. Remote-access tools on OT-tagged devices (tag HMI / SCADA / EWS devices in Defender first)
DeviceProcessEvents
| where Timestamp > ago(30d)
| join kind=inner (DeviceInfo | where DeviceManualTags has_any ("OT","SCADA","HMI","EWS") | distinct DeviceId) on DeviceId
| where FileName in~ ("anydesk.exe","teamviewer.exe","teamviewer_service.exe","rustdesk.exe","screenconnect.clientservice.exe",
                      "tvnserver.exe","winvnc.exe","ultravnc.exe","ngrok.exe","chisel.exe","plink.exe","atera_agent.exe","splashtop.exe")
| summarize First=min(Timestamp), Count=count() by DeviceName, FileName, ProcessCommandLine, AccountName
| order by First desc
```

```kql
// 3. New interactive / RDP logons to OT-tagged hosts from IPs not seen in the prior 30 days
let ot = DeviceInfo | where DeviceManualTags has_any ("OT","SCADA","HMI","EWS") | distinct DeviceId;
let baseline = DeviceLogonEvents | where Timestamp between (ago(44d) .. ago(14d)) | where DeviceId in (ot) | distinct DeviceId, RemoteIP;
DeviceLogonEvents
| where Timestamp > ago(14d) and DeviceId in (ot)
| where LogonType in ("RemoteInteractive","Network","Interactive") and ActionType == "LogonSuccess"
| join kind=leftanti baseline on DeviceId, RemoteIP
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP
```

```kql
// 4. PLC project / HMI configuration files changed (Rockwell, Siemens, Schneider, Ignition, Wonderware)
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName matches regex @"(?i)\.(acd|l5x|l5k|ap1[0-9]|zap1[0-9]|stu|sta|xef|zef|gwbk|proj|aaPKG|cfg)$"
| where ActionType in ("FileCreated","FileModified","FileDeleted","FileRenamed")
| summarize Changes=count(), Files=make_set(FileName, 20) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp, 1h)
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
// Remote-access tools on hosts tagged OT / SCADA / HMI (set Falcon grouping tags first)
#event_simpleName=ProcessRollup2
| FileName=/^(anydesk|teamviewer(_service)?|rustdesk|screenconnect.*|tvnserver|winvnc|ultravnc|ngrok|chisel|plink|atera_agent|splashtop.*)\.exe$/i
| match(file="aid_master_main.csv", field=aid, include=[ComputerName, Tags], strict=false)
| Tags=/OT|SCADA|HMI|EWS/i
| groupBy([ComputerName, FileName, CommandLine, UserName], function=count())
```

```
// Inbound remote-access / industrial ports on OT hosts from outside the OT ranges
#event_simpleName=NetworkReceiveAcceptIP4
| LocalPort=/^(3389|5900|5938|22|23|445|502|102|44818|20000|2404|4840)$/
| !cidr(RemoteAddressIP4, subnet=["<OT CIDR 1>","<OT CIDR 2>"])
| match(file="aid_master_main.csv", field=aid, include=[ComputerName, Tags], strict=false)
| Tags=/OT|SCADA|HMI|EWS/i
| groupBy([ComputerName, LocalPort, RemoteAddressIP4], function=count())
```

## Notes

Peninsula has not said how the attacker got in, so this hunt covers the usual ways into ISR and mining plants: vendor VPNs, RMM tools left after commissioning, cellular modems on wellfield RTUs, and flat IT/OT routing. Many OT hosts have no EDR agent. Where that is so, use firewall or OT monitoring logs (Dragos, Claroty, Nozomi) for queries 1 and 2, and compare PLC programs against known-good offline copies. Pair with CD-007 (industrial protocols to public IPs). Confirm that HMI images, historian data and PLC projects are backed up offline before any restoration.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
