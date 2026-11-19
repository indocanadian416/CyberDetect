# CD-014 · Web Server Processes Spawning Shells
| | |
|---|---|
| **Hunts for** | Apache, NGINX, PHP or IIS worker processes launching shells, recon commands or download tools, which indicates web-facing remote code execution or a web shell. |
| **Threat / CVE** | CVE-2026-119618 (Apache HTTP/2 RCE), PHP2Shell, NGINX CVE-2026-123007 |
| **MITRE ATT&CK** | T1190; T1059.004; T1505.003 Web Shell |
| **Category** | Initial Access / Exploitation |
| **First published** | 2026-11-12 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("httpd","apache2","httpd.exe","php","php-fpm","php-cgi","nginx","w3wp.exe")
| where FileName in~ ("sh","bash","dash","cmd.exe","powershell.exe","curl","wget","whoami","id","nc","python3","perl")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 ParentBaseFileName=/^(httpd|apache2|httpd\.exe|php|php-fpm|php-cgi|nginx|w3wp\.exe)$/i
| FileName=/^(sh|bash|dash|cmd\.exe|powershell\.exe|curl|wget|whoami|id|nc|python3|perl)$/i
| table([@timestamp, ComputerName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

CGI scripts and some PHP apps call shells legitimately; baseline and filter by command line.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
