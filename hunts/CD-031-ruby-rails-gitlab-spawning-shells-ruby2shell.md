# CD-031 · Ruby / Rails / GitLab Processes Spawning Shells (Ruby2Shell)
| | |
|---|---|
| **Hunts for** | Ruby web workers (Puma, Unicorn, Passenger, Sidekiq, GitLab's Puma) starting shells, download tools or interpreters, which is what unauthenticated RCE through Ruby2Shell would look like. Also finds Ruby runtimes below the fixed versions. |
| **Threat / CVE** | CVE-2026-132825 "Ruby2Shell" (GHSA-34m4-m9fh-gqp5): one-byte heap overflow in String case conversion, reachable without login in default Rails and classic Sinatra per Veria Labs. Fixed in Ruby 3.3.14, 3.4.13, 4.0.10; GitLab 19.6.1. Public PoC referenced in the CVE record; EPSS rose about tenfold on Nov 21. No exploitation reported; not in KEV. |
| **MITRE ATT&CK** | T1190, T1059.004 Unix Shell, T1505.003 Web Shell |
| **Category** | Initial Access / Exploitation |
| **First published** | 2026-11-21 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("ruby","puma","unicorn","passenger","bundle","sidekiq")
    or InitiatingProcessCommandLine has_any ("puma","unicorn","rails server","sidekiq","gitlab-rails","thin start")
| where FileName in~ ("sh","bash","dash","zsh","curl","wget","nc","ncat","socat","python","python3","perl","base64","chmod")
| where not(ProcessCommandLine has_any ("git-upload-pack","git-receive-pack","gitaly"))   // GitLab baseline; tune
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
// Ruby runtimes and GitLab packages to check against 3.3.14 / 3.4.13 / 4.0.10 and GitLab 19.6.1
DeviceTvmSoftwareInventory
| where SoftwareName has "ruby" or SoftwareName has "gitlab" or SoftwareName has "chatwoot"
| summarize Devices=dcount(DeviceName) by SoftwareVendor, SoftwareName, SoftwareVersion
| order by SoftwareName asc, SoftwareVersion asc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 (ParentBaseFileName=/^(ruby|puma|unicorn|passenger|bundle|sidekiq)$/i OR ParentCommandLine=/puma|unicorn|rails server|sidekiq|gitlab-rails/i)
| FileName=/^(sh|bash|dash|zsh|curl|wget|nc|ncat|socat|python3?|perl|base64|chmod)$/i
| CommandLine!=/git-upload-pack|git-receive-pack|gitaly/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

```
#event_simpleName=InstalledApplication AppName=/ruby|gitlab|chatwoot/i
| groupBy([ComputerName, AppName, AppVersion], function=count())
```

## Notes

Many apps vendor their own Ruby (GitLab Omnibus, Chatwoot, Redmine, Discourse), so updating the system Ruby is not enough; update the app. Rails apps legitimately shell out for image processing (ImageMagick, libvips), so baseline before alerting. Pair with CD-014 (web servers spawning shells).

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
