# CD-058 · VPN Intrusion to Cloud-Storage Exfiltration (Osaki Electric Smart-Meter Ransomware, Uplight Utility Data Claim)
| | |
|---|---|
| **Hunts for** | The intrusion path Osaki Electric disclosed: a VPN logon at night (Nov 15, about 1:30 AM), then bulk copying to a cloud storage service, then encryption two days later. It looks for VPN-pool logons at unusual hours by accounts with no history of them, accounts fanning out to many hosts soon after a VPN logon, and bulk-transfer tools (rclone, restic, MEGAcmd, WinSCP scripting, S3 Browser) or rclone-style `copy/sync remote:` command lines. Run it in your own estate and ask utility vendors (meter, billing, customer-program platforms) to run it in theirs. |
| **Threat / CVE** | Osaki Electric (Japanese smart-meter maker) said on 2026-11-25 that data left for an external cloud storage service before servers were encrypted on Nov 17. Meter production and shipments stopped; a staged restart is planned from Nov 27 and shipments from Dec 1. Industrial Cyber names Qilin (unverified). N0n listed Uplight (utility customer-program software) on 2026-11-25, claiming enrolment and home-energy data tied to at least 16 utility programs (unverified). No CVE or IOCs are published. |
| **MITRE ATT&CK** | T1133 External Remote Services, T1078 Valid Accounts, T1021 Remote Services, T1567.002 Exfiltration to Cloud Storage, T1486 Data Encrypted for Impact |
| **Category** | Initial Access / Exfiltration (supply chain) |
| **First published** | 2026-11-26 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// 1. VPN-pool logons between 00:00 and 05:00 (adjust to local time) by accounts with no such history in the prior 46 days
let vpnPool = dynamic(["<VPN client CIDRs>"]);
let history = DeviceLogonEvents
  | where Timestamp between (ago(60d) .. ago(14d))
  | where ipv4_is_in_any_range(RemoteIP, vpnPool) and hourofday(Timestamp) between (0 .. 5)
  | distinct AccountName;
DeviceLogonEvents
| where Timestamp > ago(14d) and ActionType == "LogonSuccess"
| where ipv4_is_in_any_range(RemoteIP, vpnPool) and hourofday(Timestamp) between (0 .. 5)
| join kind=leftanti history on AccountName
| summarize Hosts=dcount(DeviceName), HostList=make_set(DeviceName, 20), First=min(Timestamp) by AccountName, RemoteIP
| order by Hosts desc
```

```kql
// 2. Bulk-transfer tools and rclone-style command lines
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("rclone.exe","restic.exe","megacmd.exe","megacmdserver.exe","megasync.exe","winscp.com","s3browser.exe","s3browser-cli.exe")
     or ProcessCommandLine matches regex @"(?i)\s(copy|sync|move)\s+\S+\s+\S+:"
     or ProcessCommandLine has_any ("--transfers","--multi-thread-streams","--no-check-certificate")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## Microsoft Sentinel (KQL)

```kql
// 3. VPN gateway logs: successful logins from countries or ASNs not seen for that user in 60 days
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceProduct has_any ("VPN","GlobalProtect","FortiGate","AnyConnect","Pulse","SSL") and Activity has_any ("login","logon","connected","authentication success")
| extend Country = tostring(geo_info_from_ip_address(SourceIP).country)
| join kind=leftanti (CommonSecurityLog | where TimeGenerated between (ago(60d) .. ago(14d))
    | where DeviceProduct has_any ("VPN","GlobalProtect","FortiGate","AnyConnect","Pulse","SSL")
    | extend Country = tostring(geo_info_from_ip_address(SourceIP).country)
    | distinct SourceUserName, Country) on SourceUserName, Country
| project TimeGenerated, SourceUserName, SourceIP, Country, DeviceProduct, Activity
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2
| FileName=/^(rclone|restic|megacmd|megacmdserver|megasync|s3browser(-cli)?)(\.exe)?$/i
   or CommandLine=/\s(copy|sync|move)\s+\S+\s+\S+:/i
   or CommandLine=/--(transfers|multi-thread-streams)/i
| groupBy([ComputerName, UserName, FileName, CommandLine], function=count())
```

```
// Network logons right after a VPN session: one account touching many hosts in 2 hours
#event_simpleName=UserLogon LogonType=3
| in(field="RemoteAddressIP4", values=["<VPN pool IPs>"])
| bucket(span=2h, field=[UserName], function=count(field=ComputerName, distinct=true, as=Hosts))
| Hosts > 10
```

## Notes

The bulk-transfer tool list is a starting set; add any tools your vendors use legitimately to an allow-list per host. For utilities: ask Uplight and meter or billing vendors whether they have run equivalent checks, and rotate API keys, SFTP accounts and VPN accounts you share with them. Pair with CD-008 (ransomware precursors).

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
