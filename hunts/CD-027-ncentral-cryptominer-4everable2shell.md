# CD-027 · Crypto Miners on RMM Servers (N-central 4EverAble2Shell)
| | |
|---|---|
| **Hunts for** | XMRig and other Monero miners, mining-pool connections and Stratum command lines, especially on N-central and other RMM servers. Huntback found XMRig on 21 N-central servers, 19 of them already on Hotfix 2. |
| **Threat / CVE** | N-central 4EverAble2Shell / Agent2Shell (fixed in 2026.4 HF3, build 2026.4.1.39); public PoC for all 17 HF3 CVEs |
| **MITRE ATT&CK** | T1190, T1496 Resource Hijacking |
| **Category** | Impact / Post-Exploitation |
| **First published** | 2026-11-20 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("xmrig","xmrig.exe")
    or ProcessCommandLine has_any ("stratum+tcp","stratum+ssl","--donate-level","--coin=monero","-a rx/0","randomx")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("supportxmr","nanopool","hashvault","moneroocean","minexmr","c3pool","2miners","herominers")
    or (RemotePort in (3333,4444,5555,7777,14433,14444,45700)
        and InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe"))
| summarize Connections=count(), Urls=make_set(RemoteUrl, 10), Ports=make_set(RemotePort) by DeviceName, InitiatingProcessFileName
| order by Connections desc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 (FileName=/^xmrig/i OR CommandLine=/stratum\+(tcp|ssl)|--donate-level|--coin=monero|-a rx\/0/i)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

```
#event_simpleName=DnsRequest DomainName=/(supportxmr|nanopool|hashvault|moneroocean|minexmr|c3pool|2miners|herominers)/i
| table([@timestamp, ComputerName, DomainName, ContextBaseFileName])
```

## Notes

The N-central server is a Linux appliance and often has no EDR; check it directly (`ps`, crontab, systemd units, CPU load) and use your firewall logs for pool traffic. A miner proves the server was taken over; treat it as full compromise of the RMM and everything it manages, not as a nuisance. Pair with CD-016 (Java servers spawning shells) and CD-003 (new local accounts).

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
