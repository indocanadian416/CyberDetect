# CD-011 · Siemens Software Center DLL Side-Loading
| | |
|---|---|
| **Hunts for** | SiemensSoftwareCenter.exe running from the per-user provisioning folder or launched by msiexec, which matches attackers side-loading a malicious DLL beside a signed Siemens installer (AllMyBasic.msi) on engineering workstations. |
| **Threat / CVE** | CVE-2026-110936 (Siemens Software Center, CISA KEV) |
| **MITRE ATT&CK** | T1574.001 DLL Search Order Hijacking |
| **Category** | Execution / Defense Evasion |
| **First published** | 2026-11-11 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "SiemensSoftwareCenter.exe"
| where FolderPath has @"\AppData\Local\Programs\SM Software Provisioning Service" or InitiatingProcessFileName =~ "msiexec.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, InitiatingProcessFileName, ProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 FileName=/^SiemensSoftwareCenter\.exe$/i
| ImageFileName=/SM Software Provisioning Service/i OR ParentBaseFileName=/^msiexec\.exe$/i
| table([@timestamp, ComputerName, UserName, ImageFileName, ParentBaseFileName, CommandLine])
```

## Notes

Fixed in Software Center 4.0.9.8. Legitimate installs also match; review against your change records.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
