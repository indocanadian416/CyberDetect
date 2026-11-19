# CD-013 · SCKit Network Indicators and Unknown ScreenConnect Instances
| | |
|---|---|
| **Hunts for** | Connections and DNS lookups to SCKit infrastructure, plus an inventory of every ScreenConnect client instance ID in the estate so rogue instances stand out. |
| **Threat / CVE** | ScreenConnect / SCKit worm (Huntress) |
| **MITRE ATT&CK** | T1219; T1071 Application Layer Protocol |
| **Category** | Command and Control |
| **First published** | 2026-11-12 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("185.99.255.28","155.94.150.39")
    or RemoteUrl has_any ("newnewnew.gotdns.org","soxnewwork.homedns.org","sc.payproofkit.com","cdn007-digitaldownloads.com","ns.mo7sen.dev")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
```

```kql
// Every ScreenConnect client instance ID in your estate; investigate any you do not recognize
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName startswith "ScreenConnect."
| extend InstanceId = extract(@"ScreenConnect Client \(([0-9a-f]{16})\)", 1, FolderPath)
| where isnotempty(InstanceId)
| summarize Devices=dcount(DeviceName), FirstSeen=min(Timestamp) by InstanceId
| order by FirstSeen desc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=DnsRequest DomainName=/^(newnewnew\.gotdns\.org|soxnewwork\.homedns\.org|sc\.payproofkit\.com|cdn007-digitaldownloads\.com|ns\.mo7sen\.dev)$/i
| table([@timestamp, ComputerName, DomainName, ContextBaseFileName])
```

```
#event_simpleName=NetworkConnectIP4 (RemoteAddressIP4="185.99.255.28" OR RemoteAddressIP4="155.94.150.39")
| join(query={#data_source_name=aidmaster | groupBy([aid], function=selectLast([ComputerName]))}, field=[aid], include=[ComputerName])
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort])
```

```
#event_simpleName=ProcessRollup2 FileName=/^ScreenConnect\./i
| regex("ScreenConnect Client \\((?<InstanceId>[0-9a-f]{16})\\)", field=ImageFileName)
| groupBy([InstanceId], function=[count(aid, distinct=true, as=Hosts), min(@timestamp, as=FirstSeen)])
```

## Notes

Known rogue client IDs: 2588ef5c15954b10, ed630cc2c873b091. The two dynamic-DNS hostnames sit on shared providers; match the full hostname only.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
