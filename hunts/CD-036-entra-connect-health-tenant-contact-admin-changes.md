# CD-036 · Entra Tenant Contact, Connect Health and Admin Changes (Connect Health API Exposure)
| | |
|---|---|
| **Hunts for** | Changes to tenant technical/admin contact details, Connect Health settings and privileged role assignments, plus phishing or sign-in attempts aimed at the admin and technical-contact addresses that the Entra Connect Health flaw exposed. |
| **Threat / CVE** | Microsoft Entra Connect Health cloud monitoring API flaw (no CVE). Introduced Jul 23, detected Nov 9, fixed server-side Nov 19, 2026. Attackers read tenant ID, display name, initial domain, sync status, licence tier and admin / technical contact emails (read-only). Microsoft found no changes to monitoring settings. Reported Nov 22 via a customer notice (Cyber Security News). |
| **MITRE ATT&CK** | T1589.002 Gather Victim Identity Information: Email Addresses, T1566 Phishing, T1098.003 Account Manipulation: Additional Cloud Roles |
| **Category** | Cloud Identity |
| **First published** | 2026-11-22 (Daily Threat Review: Energy and Mining) |

## Microsoft Sentinel (Entra ID AuditLogs)

```kql
AuditLogs
| where TimeGenerated > ago(120d)   // exposure window starts Jul 23
| where OperationName has_any ("Update company information","Set company information","Update technical contact","Set DirSyncEnabled flag","Update service principal","Add member to role","Add eligible member to role")
    or TargetResources has_any ("Connect Health","ADHybridHealthService","Azure AD Connect Health")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| project TimeGenerated, OperationName, Actor, Result, TargetResources
| order by TimeGenerated desc
```

```kql
// Sign-in pressure on the exposed contact addresses (fill in your admin / technical contacts)
let contacts = dynamic(["admin@contoso.com","itcontact@contoso.com"]);
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName in~ (contacts)
| summarize Attempts=count(), Failures=countif(ResultType != "0"), IPs=dcount(IPAddress), Countries=make_set(LocationDetails.countryOrRegion) by UserPrincipalName, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

## Microsoft Defender XDR (KQL)

```kql
// Phishing delivered to the exposed contact addresses since the flaw was introduced
let contacts = dynamic(["admin@contoso.com","itcontact@contoso.com"]);
EmailEvents
| where Timestamp > ago(30d)
| where RecipientEmailAddress in~ (contacts)
| where EmailDirection == "Inbound"
| where ThreatTypes has_any ("Phish","Malware")
    or (Subject has_any ("Entra","Azure","tenant","Connect Health","security advisory","Service Health") and not(SenderFromDomain endswith "microsoft.com"))
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderIPv4, Subject, ThreatTypes, DeliveryAction
```

## CrowdStrike Falcon (CQL)

```
// Falcon Next-Gen SIEM with the Microsoft Entra ID connector; field names vary by parser, confirm in your console
#Vendor="microsoft" #event.dataset=/entraid\.audit|azure\.auditlogs/i
| event.action=/company information|technical contact|DirSyncEnabled|Add member to role|Add eligible member to role/i
| table([@timestamp, event.action, user.name, source.ip, event.outcome])
```

## Notes

The exposure is read-only reconnaissance, so the follow-on risk is targeted phishing and help-desk pretexting against the named admins. Check Azure Service Health for the advisory to see if your tenant was listed, and run Microsoft's read-only GetTenant script to see what the API could return. Microsoft says no passwords, hashes, tokens or valid keys were exposed. Replace the placeholder addresses before running.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
