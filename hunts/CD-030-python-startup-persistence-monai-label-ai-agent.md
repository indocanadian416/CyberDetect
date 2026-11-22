# CD-030 · Python Startup-File Persistence and Reverse Shells (MONAI Label zero-day, Cairn AI agents)
| | |
|---|---|
| **Hunts for** | Python "runs at every interpreter start" persistence (new `.pth`, `sitecustomize.py` or `usercustomize.py` files in `site-packages`), Python one-liner reverse shells, and Python AI/ML servers (MONAI Label, Jupyter, model servers) spawning shells. This is how the Cairn agents kept root on a university server after writing files through the MONAI Label path traversal. |
| **Threat / CVE** | CVE-2026-133968 (GHSA-qc22-rmgc-vg94): MONAI Label up to 0.8.5, path traversal in `PUT /datastore/image` leading to RCE. Auth is off by default. Fix merged, no patched release yet. Exploited from Sept 2026 by a China-nexus actor (Amazon, moderate confidence) using autonomous Cairn agents. Not in KEV. |
| **MITRE ATT&CK** | T1190, T1546.018 Python Startup Hooks, T1059.006 Python, T1090 Proxy |
| **Category** | Persistence / Execution |
| **First published** | 2026-11-21 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// New or changed Python startup hooks. pip/conda installs create .pth files legitimately; review the rest.
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("site-packages","dist-packages")
| where FileName endswith ".pth" or FileName in~ ("sitecustomize.py","usercustomize.py")
| where not(InitiatingProcessCommandLine has_any ("pip install","pip3 install","-m pip","conda install","uv pip","poetry install"))
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
// Python one-liner reverse shells and pty upgrades
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName startswith "python"
| where ProcessCommandLine has "socket" and ProcessCommandLine has_any ("connect(","dup2","pty.spawn","subprocess")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
// Python ML/annotation servers spawning shells or download tools
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName startswith "python"
| where InitiatingProcessCommandLine has_any ("monailabel","start_server","jupyter","uvicorn","gunicorn","mlflow","tritonserver")
| where FileName in~ ("sh","bash","dash","zsh","curl","wget","nc","ncat","socat","chmod","base64")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=/Written$/ FilePath=/(site|dist)-packages/i FileName=/(\.pth|sitecustomize\.py|usercustomize\.py)$/i
| table([@timestamp, ComputerName, FilePath, FileName, ContextBaseFileName])
```

```
#event_simpleName=ProcessRollup2 FileName=/^python/i CommandLine=/socket/i CommandLine=/connect\(|dup2|pty\.spawn|subprocess/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

```
#event_simpleName=ProcessRollup2 ParentBaseFileName=/^python/i FileName=/^(sh|bash|dash|zsh|curl|wget|nc|ncat|socat)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

Many research and data-science boxes (including geoscience, reservoir and mineral-exploration modelling in this sector) run Python servers with no login on internal networks. Inventory MONAI Label (0.8.5 or earlier), put it behind authentication and a firewall until a release ships. Falcon file-write event names differ on Linux; confirm which `*Written` events your sensor emits. Amazon published no IPs, domains or hashes for this campaign.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
