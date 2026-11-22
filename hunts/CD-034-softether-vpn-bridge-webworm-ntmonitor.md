# CD-034 · Rogue SoftEther VPN Bridge (Webworm "NtMonitor VPN")
| | |
|---|---|
| **Hunts for** | A rebuilt SoftEther VPN Bridge running on a Windows host as a covert tunnel into the internal network: the `SEVPNBRIDGE` service, the `netcapa.exe` file name, "Network Monitor Software" / "Network Systems Solutions Inc." metadata, `setting.conf` files, and HTTP beacons to `/update/alive.cgi` and `/update/picture.cgi`. Also any SoftEther binary you did not deploy. |
| **Threat / CVE** | Webworm (China-aligned espionage, Rapid7 moderate confidence), reported by Rapid7 on Nov 19, 2026. Misuse of a legitimate SoftEther feature, not a vulnerability. Targets: government organisations, mainly in Europe. Non-test configurations pointed to AS20473 (Vultr / The Constant Company). No IPs or domains published. |
| **MITRE ATT&CK** | T1572 Protocol Tunneling, T1133 External Remote Services, T1543.003 Windows Service, T1036.005 Masquerading: Match Legitimate Name, T1071.001 Web Protocols |
| **Category** | Command and Control / Persistence |
| **First published** | 2026-11-22 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// SoftEther bridge service or renamed binary
union
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType == "ServiceInstalled"
 | where AdditionalFields has_any ("SEVPNBRIDGE","SoftEther","vpnbridge","netcapa")),
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where FileName in~ ("netcapa.exe","vpnbridge.exe","vpnserver.exe","vpnclient.exe","vpncmd.exe")
     or ProcessVersionInfoCompanyName has_any ("SoftEther","Network Systems Solutions")
     or ProcessVersionInfoProductName has_any ("SoftEther","NtMonitor","Network Monitor Software")
     or ProcessCommandLine has "SEVPNBRIDGE")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, AdditionalFields, SHA256
```

```kql
// Encrypted config named setting.conf next to an unknown binary
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "setting.conf"
| where not(FolderPath has_any (@"\Program Files\","/etc/"))
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessSHA256
```

```kql
// Beacon paths (needs a proxy / firewall log in Sentinel; Defender URL fields only show some HTTP)
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("/update/alive.cgi","/update/picture.cgi")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=/^(ProcessRollup2|ServiceStarted|InstalledService)$/
| FileName=/^(netcapa|vpnbridge|vpnserver|vpnclient|vpncmd)\.exe$/i OR CommandLine=/SEVPNBRIDGE|SoftEther|vpnbridge/i OR ServiceDisplayName=/SEVPNBRIDGE|SoftEther/i
| table([@timestamp, ComputerName, UserName, #event_simpleName, FileName, CommandLine, ServiceDisplayName, SHA256HashData])
```

```
#event_simpleName=/Written$/ FileName=/^setting\.conf$/i
| FilePath!=/Program Files/i
| table([@timestamp, ComputerName, FilePath, FileName, ContextBaseFileName])
```

## Notes

Only a partial hash prefix (`90e7…`) was published, so it is not usable as a match. Rapid7 found no added command-execution backdoor: the risk is the bridge itself, which makes the host a route into the LAN. The beacon handshake is `POST /update/picture.cgi` with `Content-Type: image/jpeg`; search proxy logs for that pair. Vultr (AS20473) is a large hosting provider: outbound traffic to it is a pivot, not a verdict. If you use SoftEther legitimately, allow-list by signer and path.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
