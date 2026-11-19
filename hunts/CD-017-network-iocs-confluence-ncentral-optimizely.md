# CD-017 · Network Indicators: Confluence/Axis, N-central, Optimizely, SCKit Wave 2
| | |
|---|---|
| **Hunts for** | Sweep for connections and DNS lookups to infrastructure reported in the Confluence/Axis and N-central intrusions, the Optimizely injection and the second SCKit wave. |
| **Threat / CVE** | CVE-2026-90436; N-central exploitation; Optimizely Web injection; CVE-2026-84869 |
| **MITRE ATT&CK** | T1071; T1572 Protocol Tunneling |
| **Category** | Command and Control |
| **First published** | 2026-11-19 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
let ips = dynamic(["192.238.253.176","5.133.47.243","163.182.68.109","104.13.106.166","157.20.241.16","139.99.69.109","79.76.51.56"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (ips)
    or RemoteUrl has_any ("free.pinggy.net","1688360.cc","masterdarky.com")
    or (RemoteUrl has_any ("trycloudflare.com","webhook.site")
        and InitiatingProcessFileName in~ ("java","java.exe","curl","bash","sh"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=/^(192\.238\.253\.176|5\.133\.47\.243|163\.182\.68\.109|104\.13\.106\.166|157\.20\.241\.16|139\.99\.69\.109|79\.76\.51\.56)$/
| join(query={#data_source_name=aidmaster | groupBy([aid], function=selectLast([ComputerName]))}, field=[aid], include=[ComputerName])
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort])
```

```
#event_simpleName=DnsRequest DomainName=/(\.free\.pinggy\.net|1688360\.cc|masterdarky\.com)$/i
| table([@timestamp, ComputerName, DomainName, ContextBaseFileName])
```

## Notes

trycloudflare.com and webhook.site are shared legitimate services; the query only flags them from server or shell processes. IOC sweeps age quickly, so keep the lookback short.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
