# CD-010 · ClickFix: Commands From the Run Dialog and finger.exe Abuse
| | |
|---|---|
| **Hunts for** | Users pasting attacker commands into Win+R (RunMRU registry writes), finger.exe used as a downloader, and Explorer launching encoded or downloading PowerShell/mshta/wscript/cmd. |
| **Threat / CVE** | ClickFix / Romulus platform (Siemens installer lure) |
| **MITRE ATT&CK** | T1204.004 Malicious Copy and Paste |
| **Category** | Execution |
| **First published** | 2026-11-11 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
let runDialog = DeviceRegistryEvents
    | where Timestamp > ago(14d) and ActionType == "RegistryValueSet"
    | where RegistryKey has @"\Explorer\RunMRU"
    | project Timestamp, DeviceName, Source="RunMRU", Detail=RegistryValueData;
let finger = DeviceProcessEvents
    | where Timestamp > ago(14d) and FileName =~ "finger.exe"
    | project Timestamp, DeviceName, Source="finger.exe", Detail=ProcessCommandLine;
let shells = DeviceProcessEvents
    | where Timestamp > ago(14d) and InitiatingProcessFileName =~ "explorer.exe"
    | where FileName in~ ("powershell.exe","mshta.exe","wscript.exe","cmd.exe")
    | where ProcessCommandLine has_any ("iex","DownloadString","-enc","-EncodedCommand","mshta","http")
    | project Timestamp, DeviceName, Source="explorer child", Detail=ProcessCommandLine;
union runDialog, finger, shells
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2
| (FileName=/^finger\.exe$/i)
  OR (ParentBaseFileName=/^explorer\.exe$/i FileName=/^(powershell|mshta|wscript|cmd)\.exe$/i CommandLine=/(iex|DownloadString|-enc|-EncodedCommand|mshta|http)/i)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
