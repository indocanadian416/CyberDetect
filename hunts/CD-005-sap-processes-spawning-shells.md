# CD-005 · SAP Kernel Processes Spawning Shells
| | |
|---|---|
| **Hunts for** | SAP dispatcher, ICM, Web Dispatcher, Gateway, Message Server or Enqueue processes launching a shell or download tool, which indicates code execution as the sidadm account. |
| **Threat / CVE** | SAP Nov 2026 CVSS 10 flaws: ICM2SHELL (CVE-2026-76964, CVE-2026-89126), PROXYGATE (CVE-2026-89103), SAML2 bypass (CVE-2026-120017) |
| **MITRE ATT&CK** | T1190; T1059.004 Unix Shell |
| **Category** | Initial Access / Exploitation |
| **First published** | 2026-11-11 (reused 11-12) (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("disp+work","disp+work.exe","icman","icman.exe","sapwebdisp","sapwebdisp.exe","gwrd","gwrd.exe","msg_server","msg_server.exe","enserver","enserver.exe")
| where FileName in~ ("sh","bash","dash","csh","cmd.exe","powershell.exe","curl","wget","whoami","id","nc","python3","perl")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 ParentBaseFileName=/^(disp\+work|icman|sapwebdisp|gwrd|msg_server|enserver)(\.exe)?$/i
| FileName=/^(sh|bash|dash|csh|cmd\.exe|powershell\.exe|curl|wget|whoami|id|nc|python3|perl)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

Process names come from SAP's architecture, not a vendor detection guide; confirm them on your hosts. SAP admin scripts may need filtering by account and command line. Sigma version: sigma/sap-server-process-spawning-shell.yml.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
