# CD-063 · Volant Manticore: KuboShell IPFS/Pinata Backdoor, Rogue NetLock / N-able / MeshCentral RMM and Published IOCs
| | |
|---|---|
| **Hunts for** | The Iran-nexus Volant Manticore toolset Check Point published on 2026-11-24: the KuboShell backdoor that polls the Pinata IPFS pinning service every 60 seconds and stages files as `C:\Users\Public\<MAC>.log` and `<MAC>re.txt`; NetLock RMM, N-able RMM and MeshCentral agents installed from CV, seminar or "Excel Online" lures; the group's first-hands-on recon commands; and Check Point's network and file IOCs. |
| **Threat / CVE** | Volant Manticore (Check Point Research, 2026-11-24; The Hacker News, Industrial Cyber 2026-11-26): Iran-nexus espionage, assessed as former MuddyWater operators, active since at least September 2025. Targets: telecoms, airlines and critical infrastructure in Cyprus, and Saudi healthcare from September 2026. No energy victim is named, but the tradecraft (phishing to RMM, likely Fortinet SSL VPN access) matches what Iranian groups use against Gulf and Mediterranean energy firms. No CVE. |
| **MITRE ATT&CK** | T1566.001 Spearphishing Attachment, T1204.002 Malicious File, T1219 Remote Access Software, T1102 Web Service (IPFS/Pinata C2), T1059.001 PowerShell, T1548.002 Bypass UAC (elevation prompt), T1033 System Owner/User Discovery, T1069.002 Domain Groups |
| **Category** | Initial Access / Command and Control |
| **First published** | 2026-11-27 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// 1. KuboShell staging files and Pinata / IPFS gateway use from non-browser processes
let pinata = dynamic(["api.pinata.cloud","uploads.pinata.cloud","gateway.pinata.cloud","mypinata.cloud"]);
union
 (DeviceFileEvents | where Timestamp > ago(30d)
   | where FolderPath startswith @"C:\Users\Public\" and FileName matches regex @"^[0-9A-Fa-f]{12}(re)?\.(log|txt)$"
   | project Timestamp, DeviceName, Evidence=strcat(FolderPath), Proc=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine),
 (DeviceNetworkEvents | where Timestamp > ago(30d)
   | where RemoteUrl has_any (pinata)
   | where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","node.exe")
   | project Timestamp, DeviceName, Evidence=RemoteUrl, Proc=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine)
| order by Timestamp desc
```

```kql
// 2. Published Volant Manticore IOCs (Check Point, 2026-11-24)
let ips = dynamic(["185.205.187.107","185.205.187.108","185.205.187.109","185.106.102.70","185.221.222.185","95.182.88.89","185.253.118.221","88.119.170.218","88.119.171.245","213.252.232.131","213.252.245.44","213.252.245.60","217.60.5.55","217.60.5.75","217.60.5.87","45.38.170.31","192.142.46.141","94.126.227.67"]);
let doms = dynamic(["gatewaynet.site","cnpcyprus.net","cabelenet.com","primtel-tel.com","primetel-tel.com","webmail-eac.com","gapgroups.com","medochomie.com","aegeneair.com","dpwords.com","websitegate.net","portal-gateway.net","corenewsnetwork.com","liveupdatenews.net"]);
let hashes = dynamic(["684f748deceabf0fbb789ce11cc748ec62ea7e218f44289557e733509ec9b250","8657c350a2cf338721ade0bba8bd976cdd0c6e21fb7d5052eec24f8a034d7f7f","27f36e562015365017c1458a5944b4f03cb13049f3b268bb919fcff7f83c459f","3239b5916a3462e17ed3110083f3310c58bf1c74aca75e20ddb8bfa7b7b519fb","2477bbf0ab3f0c9db73fcb2f5f9dfe8cf6703a88862a7c98a5de6f349cd8833f","625f86e71a4b99c1fb9764a98e81901158ef0b1f6b0374b4cf1753f58bb3b858","31782222f017e5340261f0cb6d1b0bbbd9eb8309bd56a67a628e7335bdb1be4f","a4ef03a850d6a9bc590d4c074230f09848309c95c92a62a9d32c5d0be7573f52","648365b4983f3468b0f077c30110d6271e6f0c9a870ed6769be774f87f5c2b08","68ed37807c4c41541c3fb5afa3763b514be0b5d3086e8864c1e67a74580f4535"]);
union isfuzzy=true
 (DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in (ips) or RemoteUrl has_any (doms)
   | project Timestamp, DeviceName, Hit=coalesce(RemoteUrl, RemoteIP), Proc=InitiatingProcessFileName),
 (DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (hashes)
   | project Timestamp, DeviceName, Hit=SHA256, Proc=FileName),
 (DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (hashes)
   | project Timestamp, DeviceName, Hit=SHA256, Proc=FileName),
 (EmailEvents | where Timestamp > ago(30d) | where SenderFromAddress in~ ("mahaalazami@protonmail.com","u0138738662@proton.me")
   | project Timestamp, DeviceName=RecipientEmailAddress, Hit=SenderFromAddress, Proc=Subject)
```

```kql
// 3. RMM agents that are not on your approved list, first seen in the last 30 days
let approvedRmm = dynamic(["<your approved RMM binaries>"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("netlock","meshagent","MeshCentral","n-able","N-central","BASupSrvc","agent.exe") or ProcessVersionInfoCompanyName has_any ("NetLock","N-able","MeshCentral")
| where FileName !in~ (approvedRmm)
| summarize First=min(Timestamp), Hosts=dcount(DeviceName), Parents=make_set(InitiatingProcessFileName, 5), Cmd=any(ProcessCommandLine) by FileName, ProcessVersionInfoCompanyName
| order by First desc
```

```kql
// 4. Operator recon set seen in the report, run by one account within 15 minutes
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("quser", "whoami", "ipconfig", "net group \"domain admins\" /domain", "nslookup -q=srv _kerberos._tcp")
| summarize Cmds=make_set(ProcessCommandLine, 10), N=dcount(ProcessCommandLine) by DeviceName, AccountName, bin(Timestamp, 15m)
| where N >= 3
```

## CrowdStrike Falcon (CQL)

```
// KuboShell staging files
#event_simpleName=/^(NewScriptWritten|NewExecutableWritten|.*FileWritten)$/
| TargetFileName=/\\Users\\Public\\[0-9A-Fa-f]{12}(re)?\.(log|txt)$/i
| groupBy([ComputerName, TargetFileName, ContextBaseFileName], function=count())
```

```
// Pinata / IPFS lookups from non-browser processes
#event_simpleName=DnsRequest DomainName=/pinata\.cloud$/i
| !in(field="ContextBaseFileName", values=["chrome.exe","msedge.exe","firefox.exe","brave.exe"], ignoreCase=true)
| groupBy([ComputerName, DomainName, ContextBaseFileName], function=count())
```

```
// Published IPs and domains
#event_simpleName=/^(NetworkConnectIP4|DnsRequest)$/
| in(field="RemoteAddressIP4", values=["185.205.187.107","185.205.187.108","185.205.187.109","185.106.102.70","185.221.222.185","95.182.88.89","185.253.118.221","88.119.170.218","88.119.171.245","213.252.232.131","213.252.245.44","213.252.245.60","217.60.5.55","217.60.5.75","217.60.5.87","45.38.170.31","192.142.46.141","94.126.227.67"])
  or DomainName=/(gatewaynet\.site|cnpcyprus\.net|cabelenet\.com|primt?e?l?-tel\.com|webmail-eac\.com|gapgroups\.com|medochomie\.com|aegeneair\.com|dpwords\.com|websitegate\.net|portal-gateway\.net|corenewsnetwork\.com|liveupdatenews\.net)$/i
| groupBy([aid, RemoteAddressIP4, DomainName, ContextBaseFileName], function=count())
```

```
// Published hashes (KuboShell, lure document, rogue RMM)
#event_simpleName=ProcessRollup2
| in(field="SHA256HashData", values=["684f748deceabf0fbb789ce11cc748ec62ea7e218f44289557e733509ec9b250","8657c350a2cf338721ade0bba8bd976cdd0c6e21fb7d5052eec24f8a034d7f7f","625f86e71a4b99c1fb9764a98e81901158ef0b1f6b0374b4cf1753f58bb3b858","31782222f017e5340261f0cb6d1b0bbbd9eb8309bd56a67a628e7335bdb1be4f","a4ef03a850d6a9bc590d4c074230f09848309c95c92a62a9d32c5d0be7573f52","648365b4983f3468b0f077c30110d6271e6f0c9a870ed6769be774f87f5c2b08","68ed37807c4c41541c3fb5afa3763b514be0b5d3086e8864c1e67a74580f4535"])
| groupBy([ComputerName, FileName, SHA256HashData], function=count())
```

## Notes

The hash list is the KuboShell, lure-document and RMM subset; Check Point's report also lists about 50 Homa Framework stage hashes and the archive hashes. Intel MCP (2026-11-27): 185.205.187.109 is AS197648 Cloudlayer8 (CY), 88.119.170.218 is AS61272 Bacloud (LT, hosted NL), 217.60.5.55 is AS56971 CGI Global (HK, hosted FR); none is DROP-listed or a Tor exit. gatewaynet.site was registered at Namecheap on 2026-11-10. NetLock, N-able and MeshCentral are legitimate tools, so query 3 needs your allow-list. Pinata is used legitimately by Web3 developers.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
