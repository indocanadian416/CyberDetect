# CD-042 · Azure API Management Classic: Secret Reads and Use of Exposed Credentials (Equinor / Skagerak Energi)
| | |
|---|---|
| **Hunts for** | Secret-read and admin operations on Azure API Management (APIM) Classic instances, Key Vault secret reads by APIM managed identities from unusual IPs or volumes, subscription keys suddenly used from new IP addresses, and new-IP sign-ins by the identity-provider / OpenID Connect client apps whose secrets APIM held. |
| **Threat / CVE** | Azure APIM Classic flaw (no CVE; Microsoft advisory MZK9-GH0). Unauthorised access to management functions let attackers run admin operations and read Named Values, IdP and OIDC client secrets, subscription keys and direct management API tokens. Microsoft identified it Nov 18 and closed the access path Nov 19, 2026; **the fix does not invalidate secrets taken before it**. Norway's NSM linked it to the Equinor (detected Nov 17) and Skagerak Energi (Nov 18) incidents and says other sectors in Norway and abroad were hit. Affected: Classic Developer, Basic, Standard, Premium. Not affected: Classic Consumption, all v2 tiers. |
| **MITRE ATT&CK** | T1552 Unsecured Credentials, T1528 Steal Application Access Token, T1078.004 Valid Accounts: Cloud Accounts, T1098.001 Account Manipulation: Additional Cloud Credentials |
| **Category** | Cloud / Credential Access |
| **First published** | 2026-11-24 (Daily Threat Review: Energy and Mining) |

## Microsoft Sentinel (KQL)

```kql
// 1. Secret reads and admin changes on APIM (Azure Activity)
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has "MICROSOFT.APIMANAGEMENT/SERVICE"
| where OperationNameValue has_any ("LISTSECRETS","LISTVALUE","REGENERATE","TENANT/ACCESS",
        "NAMEDVALUES/WRITE","IDENTITYPROVIDERS/WRITE","OPENIDCONNECTPROVIDERS/WRITE",
        "BACKENDS/WRITE","POLICIES/WRITE","USERS/WRITE","APIS/POLICIES/WRITE")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, _ResourceId
| order by TimeGenerated desc
```

```kql
// 2. Subscription keys used from IPs never seen before the attack window
//    (needs APIM resource-specific diagnostic logs)
let baseline = ApiManagementGatewayLogs
    | where TimeGenerated between (ago(60d) .. datetime(2026-11-17))
    | distinct ApimSubscriptionId, CallerIpAddress;
ApiManagementGatewayLogs
| where TimeGenerated >= datetime(2026-11-17)
| join kind=leftanti baseline on ApimSubscriptionId, CallerIpAddress
| summarize First=min(TimeGenerated), Calls=count(), Apis=make_set(ApiId, 20) by ApimSubscriptionId, CallerIpAddress
| order by Calls desc
```

```kql
// 3. Key Vault secret reads by APIM managed identities (legacy AzureDiagnostics schema)
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet","SecretList","CertificateGet","KeyGet")
| where identity_claim_xms_mirid_s has "Microsoft.ApiManagement"
| summarize Reads=count(), Secrets=dcount(id_s), IPs=make_set(CallerIPAddress, 20) by bin(TimeGenerated, 1d), Resource, identity_claim_xms_mirid_s
| order by TimeGenerated desc
```

```kql
// 4. IdP / OIDC client apps (whose secrets were in APIM) signing in from new IPs
let apimClientAppIds = dynamic(["<appId of each IdP/OIDC client configured in APIM>"]);
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| where AppId in (apimClientAppIds)
| summarize First=min(TimeGenerated), SignIns=count() by AppId, ServicePrincipalName, IPAddress, tostring(LocationDetails.countryOrRegion)
| where First >= datetime(2026-11-17)
```

## Microsoft Defender XDR (KQL)

```kql
// Azure management events in Defender for Cloud Apps
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Azure"
| where ActionType has "Microsoft.ApiManagement" and ActionType has_any ("listSecrets","listValue","regenerate")
| project Timestamp, AccountDisplayName, IPAddress, ActionType, ObjectName
```

## CrowdStrike Falcon Next-Gen SIEM (CQL)

```
// Azure Activity via the Microsoft Azure connector; field names vary by parser, confirm in your console
#Vendor="microsoft" #event.dataset=/azure\.activity/i
| event.action=/MICROSOFT\.APIMANAGEMENT\/SERVICE\/.*(LISTSECRETS|LISTVALUE|REGENERATE|NAMEDVALUES\/WRITE|BACKENDS\/WRITE)/i
| table([@timestamp, user.name, source.ip, event.action, event.outcome])
```

```
// Key Vault secret reads by APIM identities
#Vendor="microsoft" #event.dataset=/azure\.(platformlogs|keyvault)/i
| event.action=/SecretGet|SecretList/i
| Vendor.identity=/Microsoft\.ApiManagement/i
| groupBy([source.ip, Vendor.identity], function=count())
```

## Notes

The access path may have been a legacy API that wrote **no customer-visible logs** (unverified report cited by BleepingComputer), so an empty result does not mean you are safe. Do the response regardless: inventory every Classic instance (including forgotten dev/test), rotate all Named Values, IdP/OIDC client secrets, subscription keys and management tokens, move secrets to Key Vault references, map what each instance's credentials can reach, and check those backends' logs. NSM also advises checking each instance's runtime version against its published thresholds and contacting Microsoft if it is below them. No IOCs have been published. Queries 2 to 4 need APIM resource-specific diagnostics, Key Vault diagnostics and Entra SP sign-in logs to be enabled.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
