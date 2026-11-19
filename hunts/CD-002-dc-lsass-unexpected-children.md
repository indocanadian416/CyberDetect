# CD-002 · Domain Controller: Unexpected Child Processes of lsass.exe
| | |
|---|---|
| **Hunts for** | Shells and LOLBins (cmd, PowerShell, WMIC, rundll32, regsvr32) launched by lsass.exe, a sign of code execution inside the LDAP/LSASS process after exploitation. |
| **Threat / CVE** | CVE-2026-119958 (Windows LDAP RCE, CVSS 9.8) |
| **MITRE ATT&CK** | T1190 Exploit Public-Facing Application; T1059 |
| **Category** | Initial Access / Exploitation |
| **First published** | 2026-11-11 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "lsass.exe"
| where FileName in~ ("cmd.exe","powershell.exe","wmic.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 ParentBaseFileName=/^lsass\.exe$/i FileName=/^(cmd|powershell|wmic|rundll32|regsvr32)\.exe$/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
