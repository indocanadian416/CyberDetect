# CD-018 · Malicious agent-framework PyPI Package (1.26.1 / 1.26.2)
| | |
|---|---|
| **Hunts for** | The .pth files that run the credential stealer on every Python start, Python processes reaching webhook.site, and installs of the bad versions. |
| **Threat / CVE** | Microsoft agent-framework PyPI compromise (Nov 17, 2026) |
| **MITRE ATT&CK** | T1195.002; T1552.001 Credentials In Files |
| **Category** | Supply Chain |
| **First published** | 2026-11-19 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("agent_framework_meta.pth","af_runtime_diag.pth") or FolderPath has "agent_framework_meta"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine
```

```kql
// Python reaching webhook.site
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "webhook.site" and InitiatingProcessFileName startswith "python"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl
```

```kql
// Installs of the bad versions
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "agent-framework" and ProcessCommandLine has_any ("1.26.1","1.26.2")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=/FileWritten$/ FileName=/^(agent_framework_meta\.pth|af_runtime_diag\.pth)$/i
| table([@timestamp, ComputerName, FilePath, FileName, ContextBaseFileName])
```

```
#event_simpleName=DnsRequest DomainName="webhook.site" ContextBaseFileName=/^python/i
| table([@timestamp, ComputerName, DomainName, ContextBaseFileName])
```

## Notes

Also grep CI images and lockfiles (requirements.txt, poetry.lock, uv.lock) for agent-framework==1.26.1 or 1.26.2. Rotate every secret on affected hosts and runners.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
