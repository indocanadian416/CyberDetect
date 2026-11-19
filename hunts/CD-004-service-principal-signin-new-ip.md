# CD-004 · Service Principals Signing In From New IPs
| | |
|---|---|
| **Hunts for** | Entra ID service principals that successfully signed in from an IP not seen for that principal in the prior 30 days. Targets abuse of valid application credentials and stolen OAuth app tokens. |
| **Threat / CVE** | ARTEX AI-driven cloud intrusions (Chainalysis, Chainstack) |
| **MITRE ATT&CK** | T1078.004 Cloud Accounts; T1528 Steal Application Access Token |
| **Category** | Cloud Identity |
| **First published** | 2026-11-11 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
let baseline = EntraIdSpnSignInEvents
    | where Timestamp between (ago(30d) .. ago(2d)) and ErrorCode == 0
    | summarize by ServicePrincipalId, IPAddress;
EntraIdSpnSignInEvents
| where Timestamp > ago(2d) and ErrorCode == 0
| join kind=leftanti baseline on ServicePrincipalId, IPAddress
| summarize NewIPs=dcount(IPAddress), IPs=make_set(IPAddress, 10) by ServicePrincipalName, ServicePrincipalId, ResourceDisplayName
| order by NewIPs desc
```

## CrowdStrike Falcon (CQL)

Not applicable: Falcon endpoint telemetry does not carry this data. See notes.

## Notes

EntraIdSpnSignInEvents needs a Microsoft Entra ID P2 license. CrowdStrike endpoint telemetry does not cover Entra sign-ins; use Falcon Identity Protection or your cloud log source with the same logic.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
