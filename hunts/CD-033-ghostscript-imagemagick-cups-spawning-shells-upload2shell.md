# CD-033 · Ghostscript / ImageMagick / CUPS Spawning Shells (Upload2Shell)
| | |
|---|---|
| **Hunts for** | Ghostscript (`gs`, `gswin64c.exe`), ImageMagick (`convert`, `magick`), CUPS filters (`gstoraster`, `foomatic-rip`) or web workers rendering document previews that start shells, download tools or interpreters. That is what a crafted PDF/PostScript/EPS escaping the `-dSAFER` sandbox looks like on upload, webmail and print servers. Also finds Ghostscript below 10.08.0. |
| **Threat / CVE** | CVE-2026-125396 "Upload2Shell": use-after-free via `.putgstringcopy` / `.forceput` in the Type 1 font loader, bypasses `-dSAFER`. Ghostscript before 10.08.0. Demonstrated by Paulos Yibelo (pwn.ai) through WordPress/Imagick, Roundcube 1.7.2 and unauthenticated CUPS queues on Debian 13. CVSS 4.0 8.5. Research demos only; no exploitation reported; not in KEV. EPSS doubled on Nov 22 (0.0016 to 0.0035). |
| **MITRE ATT&CK** | T1190 Exploit Public-Facing Application, T1203 Exploitation for Client Execution, T1059.004 Unix Shell |
| **Category** | Initial Access / Exploitation |
| **First published** | 2026-11-22 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// Renderers and print filters starting shells or download tools
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("gs","gsc","gswin64c.exe","gswin32c.exe","convert","magick","magick.exe","gstoraster","gstopdf","foomatic-rip","pdftops","cupsd")
    or InitiatingProcessCommandLine has_any ("-dSAFER","-sDEVICE=","gstoraster","foomatic-rip")
| where FileName in~ ("sh","bash","dash","zsh","curl","wget","nc","ncat","socat","python","python3","perl","base64","chmod","cmd.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

```kql
// Web, mail and print service accounts running Ghostscript and then a shell (www-data, lp, apache, nginx)
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName in~ ("www-data","apache","nginx","lp","cups")
| where FileName in~ ("sh","bash","dash","curl","wget","nc","ncat","python3","perl")
| where InitiatingProcessCommandLine has_any ("gs ","ghostscript","convert","magick","-dSAFER")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

```kql
// Ghostscript below 10.08.0 (distros backport: check the package release, not only the version)
DeviceTvmSoftwareInventory
| where SoftwareName has "ghostscript" or SoftwareName has "imagemagick" or SoftwareName has "cups"
| summarize Devices=dcount(DeviceName) by SoftwareVendor, SoftwareName, SoftwareVersion
| order by SoftwareName asc, SoftwareVersion asc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2
| (ParentBaseFileName=/^(gs|gsc|gswin(32|64)c\.exe|convert|magick(\.exe)?|gstoraster|gstopdf|foomatic-rip|pdftops)$/i OR ParentCommandLine=/-dSAFER|-sDEVICE=|gstoraster|foomatic-rip/i)
| FileName=/^(sh|bash|dash|zsh|curl|wget|nc|ncat|socat|python3?|perl|base64|chmod|cmd\.exe|powershell\.exe|pwsh\.exe)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, ParentCommandLine])
```

```
#event_simpleName=InstalledApplication AppName=/ghostscript|ghostpdl|imagemagick|cups/i
| groupBy([ComputerName, AppName, AppVersion], function=count())
```

## Notes

Fixed upstream in Ghostscript 10.08.0; Debian 13 first shipped the fix in `10.05.1~dfsg-1+deb13u2`. WordPress fixed the upload route in 7.0.4 / 6.9.7 (CVE-2026-65640). Containers and app bundles carry their own Ghostscript copies, so host updates do not reach them. Storing a file did not trigger the bug in the research; rendering it did, so focus on the preview/thumbnail/print worker. Legitimate print filters call other filters (`sh -c` wrappers are common in CUPS), so baseline before alerting. Pair with CD-014 (web servers spawning shells).

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
