# CD-009 · cPGuard Processes Downloading or Running Scripts
| | |
|---|---|
| **Hunts for** | cPGuard processes launching curl, wget or script interpreters, which matches the hijacked update that installed a backdoor and stole credentials on about 2,950 Linux servers. |
| **Threat / CVE** | cPGuard update channel hijack (Nov 2, 2026) |
| **MITRE ATT&CK** | T1195.002 Compromise Software Supply Chain |
| **Category** | Supply Chain |
| **First published** | 2026-11-11 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessCommandLine has "cpguard" or InitiatingProcessFolderPath has "cpguard"
| where FileName in~ ("curl","wget","bash","sh","python3","perl")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 (ParentBaseFileName=/cpguard/i OR CommandLine=/cpguard/i)
| FileName=/^(curl|wget|bash|sh|python3|perl)$/
| table([@timestamp, ComputerName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

Rotate credentials on any server that ran cPGuard during the affected window.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
