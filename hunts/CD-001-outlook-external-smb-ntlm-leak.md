# CD-001 · Outlook Connecting to External SMB (NTLM Hash Leak)
| | |
|---|---|
| **Hunts for** | Outlook opening an SMB connection (445/139) to a public IP. A crafted message file can make Outlook contact an attacker's server without a warning and leak the user's NTLMv2 hash. |
| **Threat / CVE** | CVE-2026-124194 (Outlook, CISA KEV) |
| **MITRE ATT&CK** | T1187 Forced Authentication |
| **Category** | Credential Access |
| **First published** | 2026-11-11 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "outlook.exe"
| where RemotePort in (445, 139) and RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 FileName=/^outlook\.exe$/i
| join(query={#event_simpleName=NetworkConnectIP4 (RemotePort=445 OR RemotePort=139)
    | cidr(field=RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"], negate=true)},
    field=[aid, TargetProcessId], key=[aid, ContextProcessId], include=[RemoteAddressIP4, RemotePort])
| table([@timestamp, ComputerName, UserName, RemoteAddressIP4, RemotePort])
```

## Notes

Behavioral hunt based on the vendor description, not a published detection. Also consider blocking outbound SMB to the internet at the perimeter.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
