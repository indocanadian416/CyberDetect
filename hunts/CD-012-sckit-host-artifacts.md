# CD-012 · SCKit Host Artifacts (Files, Processes, Scheduled Task, Run Key)
| | |
|---|---|
| **Hunts for** | Files, command lines, the "TrapWatch" scheduled task and the "RelayTrapLiteAlert" Run value left by the SCKit toolkit pushed through compromised ScreenConnect panels. |
| **Threat / CVE** | ScreenConnect / SCKit worm (Huntress, Nov 11-13) |
| **MITRE ATT&CK** | T1219 Remote Access Tools; T1053.005 Scheduled Task; T1547.001 Run Keys |
| **Category** | Persistence |
| **First published** | 2026-11-12 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
let files = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FolderPath has @"\ProgramData\RelayTrap"
        or FileName in~ ("sckit-run.bat","sckit-decoder.ps1","sckit-loader.ps1","Panel-Lateral.ps1","ToolboxRelayUploader.exe","RelayTrap.exe","Run-Lateral-Full.bat","runnew.cmd")
    | project Timestamp, DeviceName, Source="file", Detail=strcat(FolderPath, " | ", InitiatingProcessFileName);
let procs = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any ("sckit","RelayTrap","2588ef5c15954b10","ed630cc2c873b091","mo7sen.dev")
        or FolderPath has @"\ProgramData\RelayTrap"
    | project Timestamp, DeviceName, Source="process", Detail=ProcessCommandLine;
let tasks = DeviceEvents
    | where Timestamp > ago(7d) and ActionType == "ScheduledTaskCreated"
    | where AdditionalFields has "TrapWatch"
    | project Timestamp, DeviceName, Source="scheduled task", Detail=tostring(AdditionalFields);
let runkey = DeviceRegistryEvents
    | where Timestamp > ago(7d) and RegistryValueName =~ "RelayTrapLiteAlert"
    | project Timestamp, DeviceName, Source="run key", Detail=RegistryValueData;
union files, procs, tasks, runkey
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
(#event_simpleName=ProcessRollup2
   (CommandLine=/(sckit|RelayTrap|2588ef5c15954b10|ed630cc2c873b091|mo7sen\.dev)/i
    OR ImageFileName=/\\ProgramData\\RelayTrap\\/i
    OR FileName=/^(ToolboxRelayUploader|RelayTrap)\.exe$/i))
OR (#event_simpleName=ScheduledTaskRegistered TaskName=/TrapWatch/i)
| table([@timestamp, ComputerName, #event_simpleName, UserName, ImageFileName, CommandLine, TaskName])
```

## Notes

Do not open ScreenConnect sessions to suspect hosts; isolate and clean them out of band. Toolkit file hashes change per host, so match on names and paths.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
