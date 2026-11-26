# CD-057 · Juniper Session Smart Conductor Salt Injection and Mitel MiCollab AWV Compromise (CVE-2026-103406, CVE-2026-133323, CVE-2026-133303, CVE-2026-133275, CVE-2026-133311, CVE-2026-133324)
| | |
|---|---|
| **Hunts for** | Salt master traffic (TCP 4505/4506) to a Session Smart Conductor from anything that is not one of your own SSR routers, new outbound destinations from the conductor or from MiCollab servers (callbacks after root), internet-facing access to MiCollab AWV, and shells or unusual processes on either appliance where a sensor runs. |
| **Threat / CVE** | All six added to CISA KEV 2026-11-25, due 2026-11-28. Juniper Session Smart Conductor CVE-2026-103406 (9.8): the AutomatedProvisioner runs OS commands as root from a crafted salt minion ID, so no login is needed. Fixed in 7.0.5 / 7.1.7 / 7.2.3. The conductor pushes configuration to every SD-WAN router, including routers at remote substations, wellsites and mine sites. Mitel MiCollab AWV (MISA-2026-0012): command injection (10.0), XML injection (9.0), file upload, information exposure and authentication bypass, which chain to unauthenticated command execution. Fixed in 10.3.0.18. |
| **MITRE ATT&CK** | T1190 Exploit Public-Facing Application, T1059.004 Unix Shell, T1133 External Remote Services, T1105 Ingress Tool Transfer |
| **Category** | Initial Access / Network Infrastructure |
| **First published** | 2026-11-26 (Daily Threat Review: Energy and Mining) |

## Microsoft Sentinel (KQL)

```kql
// 1. Salt traffic to the conductor from anything that is not one of your routers
let conductors = dynamic(["<Session Smart Conductor IPs>"]);
let routers    = dynamic(["<your SSR router IPs / CIDRs>"]);
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DestinationIP in (conductors) and DestinationPort in (4505, 4506)
| where not(ipv4_is_in_any_range(SourceIP, routers))
| summarize Conns=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by SourceIP, DestinationIP, DestinationPort
| order by First desc
```

```kql
// 2. New outbound destinations from either appliance in the last 14 days vs the prior 46
let appliances = dynamic(["<Session Smart Conductor IPs>","<MiCollab IPs>"]);
let baseline = CommonSecurityLog
  | where TimeGenerated between (ago(60d) .. ago(14d))
  | where SourceIP in (appliances)
  | distinct SourceIP, DestinationIP;
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where SourceIP in (appliances) and not(ipv4_is_private(DestinationIP))
| join kind=leftanti baseline on SourceIP, DestinationIP
| summarize Conns=count(), Ports=make_set(DestinationPort), Bytes=sum(SentBytes), First=min(TimeGenerated) by SourceIP, DestinationIP
| order by First desc
```

```kql
// 3. Internet sources reaching MiCollab web / AWV
let micollab = dynamic(["<MiCollab IPs>"]);
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DestinationIP in (micollab) and DestinationPort in (80, 443) and not(ipv4_is_private(SourceIP))
| summarize Requests=count(), URLs=make_set(RequestURL, 25), First=min(TimeGenerated) by SourceIP, DestinationIP
| order by Requests desc
```

## CrowdStrike Falcon (CQL)

```
// Falcon Next-Gen SIEM: salt ports to the conductor from unknown sources
destination.port=/^(4505|4506)$/
| in(field="destination.ip", values=["<conductor IPs>"])
| !cidr(source.ip, subnet=["<your SSR router CIDRs>"])
| groupBy([source.ip, destination.ip, destination.port], function=count())
```

```
// Linux sensor on the conductor / MiCollab (where supported): shells and download tools spawned by service accounts
#event_simpleName=ProcessRollup2 event_platform=Lin
| in(field="ComputerName", values=["<conductor hostnames>","<MiCollab hostnames>"])
| FileName=/^(sh|bash|dash|curl|wget|nc|ncat|socat|python3?|perl)$/
| groupBy([ComputerName, ParentBaseFileName, FileName, CommandLine, UserName], function=count())
```

## Notes

The SSR conductor uses Salt for router provisioning; ports 4505/4506 are Salt's defaults, so confirm them for your deployment. Block both ports at the conductor's firewall except from your routers. Review the conductor's audit log for new or renamed router assets, and MiCollab's admin and AWV logs for uploads and new conferences since 2026-11-16 (Mitel disclosure date). Neither vendor has published IOCs.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
