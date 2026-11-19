# CD-020 · Identity: Device-Code and Legacy-Auth Sign-ins, New MFA/Passkey Registrations
| | |
|---|---|
| **Hunts for** | Successful device-code or legacy-protocol sign-ins, and new security info, passkey or device registrations, which match OAuth token phishing and attackers adding their own MFA methods to persist. |
| **Threat / CVE** | Cold Relic (COLDRIVER) M365/Workspace intrusions; OAuth token phishing; Confluence intrusion ending in legacy-auth M365 sign-in |
| **MITRE ATT&CK** | T1528; T1078.004; T1098.005 Device Registration |
| **Category** | Cloud Identity |
| **First published** | 2026-11-19 (Daily Threat Review: Energy and Mining) |

## Microsoft Sentinel (KQL, Entra ID sign-in and audit logs)

```kql
SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0
| where AuthenticationProtocol == "deviceCode"
    or ClientAppUsed in ("Exchange ActiveSync","IMAP4","POP3","Authenticated SMTP","Other clients","Exchange Web Services","AutoDiscover","MAPI Over HTTP","Offline Address Book")
| project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, AuthenticationProtocol, IPAddress, Location
| order by TimeGenerated desc
```

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("registered security info","passkey","Register device","Add device")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), ActorIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, Actor, ActorIP, TargetResources
| order by TimeGenerated desc
```

## CrowdStrike Falcon (CQL)

Not applicable: Falcon endpoint telemetry does not carry this data. See notes.

## Notes

CrowdStrike endpoint telemetry does not cover these sign-ins; use Falcon Identity Protection or your Entra / Google Workspace log source. For Google Workspace, review new security key and passkey enrolments in the admin audit log.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
