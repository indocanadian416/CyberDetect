# CD-006 · SSH Sessions Spawning Shells (Rare Accounts)
| | |
|---|---|
| **Hunts for** | Baseline of shells launched by sshd, sorted rarest first, to spot unusual accounts or hosts after an OpenSSH authentication bypass. |
| **Threat / CVE** | CVE-2026-123158 OpenSSH "SSHole" (musl + PAM disabled, e.g. Alpine) |
| **MITRE ATT&CK** | T1190; T1059.004 |
| **Category** | Initial Access / Exploitation |
| **First published** | 2026-11-11 (reused 11-12) (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "sshd"
| where FileName in~ ("sh","bash","dash")
| summarize Sessions=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, AccountName
| order by Sessions asc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 ParentBaseFileName="sshd" FileName=/^(sh|bash|dash)$/
| groupBy([ComputerName, UserName], function=count(as=Sessions))
| sort(Sessions, order=asc)
```

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
