# CD-047 · ARTEX Self-Labelled Artifacts and Agent Cloud Behaviour (pentest-*, csai-*, artex-probe-*, ArtexProbe, i&lt;N&gt;-canary; Cognito sign-up abuse, anonymous S3, log mining)
| | |
|---|---|
| **Hunts for** | (1) Accounts, apps, IAM users/roles, role sessions, functions, buckets, pods and files that agentic frameworks name after themselves: `pentest-*`, `pentest-iNNNNNN`, `pentestprobe-*`, `csai-*` (`csai-escape`, `csai-pentest-role`, `csai-probe`), `artex-probe-NNNNN`, `ArtexProbe*`, `i<number>-probe` / `i<number>canary`, plus `probe` / `recon` with counting numbers; (2) the AWS sequence Datadog and Wiz describe: anonymous S3 reads, "learn the not-found response" probes, Cognito self-registration bursts, `FilterLogEvents` log mining at limit 1000, `GetCallerIdentity` and wide enumeration with mass `AccessDenied`; (3) on endpoints, the same names in new local accounts and files, and the web shell names reported in ARTEX intrusions. |
| **Threat / CVE** | ARTEX and related agentic frameworks (CyberStrikeAI, HexStrike, Cairn). Wiz behavioural rules: *"Session or Resource Name Matching an AI Offensive Tool Naming Pattern"* and *"AI Offensive Tool Step Counter in Session or Resource Names"*. Bitrise saw usernames `pentestprobe-1d2bf9`, `pentest-probe-v2-mbjlcuxr`, `i871-probe`, `i3694canary`. GTIG reported `artex-probe-*` files and `ArtexProbe` accounts; Datadog saw PreSignUp errors for tenant `artex-hqheizfk.invalid`. No CVE. |
| **MITRE ATT&CK** | T1136.003 Create Cloud Account, T1098 Account Manipulation, T1580 Cloud Infrastructure Discovery, T1619 Cloud Storage Object Discovery, T1552.001 Credentials In Files, T1505.003 Web Shell |
| **Category** | Persistence / Discovery |
| **First published** | 2026-11-25 (ARTEX special, from the Wiz report plus open-source reporting) |

## Naming patterns used below

```
(?i)(^|[^a-z])(pentest[-_]?(probe|recon|i\d{4,7}|role|[a-z0-9]{6,10})|csai[-_]|artex|artx[-_]|artexprobe|reconprobe|i\d{3,7}[-_]?(probe|canary))
```

Expect noise from your own pentest vendor and from QA test accounts. Exclude them by owner, not by dropping the pattern.

## Microsoft Defender XDR / Sentinel (KQL)

```kql
// 1. Self-labelled identities and resources: Entra users, apps and service principals, AWS IAM / Cognito / Lambda / S3, endpoint accounts
let agentName = @"(?i)(^|[^a-z])(pentest[-_]?(probe|recon|i\d{4,7}|role|[a-z0-9]{6,10})|csai[-_]|artex|artx[-_]|artexprobe|reconprobe|i\d{3,7}[-_]?(probe|canary))";
union isfuzzy=true
 (AuditLogs | where TimeGenerated > ago(30d)
    | where OperationName in ("Add user","Invite external user","Add application","Add service principal","Add service principal credentials","Update application – Certificates and secrets management","Add member to role","Add app role assignment to service principal")
    | mv-expand T = TargetResources
    | extend Name = coalesce(tostring(T.userPrincipalName), tostring(T.displayName))
    | where Name matches regex agentName
    | project Timestamp=TimeGenerated, Source="EntraAudit", Name, Action=OperationName, Actor=coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), IP=tostring(InitiatedBy.user.ipAddress)),
 (AWSCloudTrail | where TimeGenerated > ago(30d)
    | extend RP = parse_json(RequestParameters)
    | extend Name = coalesce(tostring(RP.userName), tostring(RP.roleName), tostring(RP.roleSessionName), tostring(RP.functionName), tostring(RP.bucketName), tostring(RP.username), tostring(RP.policyName), tostring(RP.key))
    | where Name matches regex agentName or UserIdentityArn matches regex agentName
    | project Timestamp=TimeGenerated, Source="AWSCloudTrail", Name=coalesce(Name, UserIdentityArn), Action=strcat(EventSource, " ", EventName, " ", ErrorCode), Actor=UserIdentityArn, IP=SourceIpAddress),
 (DeviceEvents | where Timestamp > ago(30d) | where ActionType == "UserAccountCreated"
    | where AccountName matches regex agentName
    | project Timestamp, Source="DeviceEvents", Name=AccountName, Action=ActionType, Actor=InitiatingProcessAccountName, IP=DeviceName),
 (DeviceFileEvents | where Timestamp > ago(30d) | where ActionType == "FileCreated"
    | where FileName matches regex @"(?i)^(artex-probe-\d{3,6}|artex-\d+\.\d+\.\d+-(linux|darwin|windows)-(amd64|arm64)\.zip|cl1217\.jsp|f1219a\.jsp|z1219\.jsp|beacon_linux_amd64|wisp-agent)$"
    | project Timestamp, Source="DeviceFileEvents", Name=strcat(FolderPath), Action=InitiatingProcessFileName, Actor=InitiatingProcessAccountName, IP=DeviceName)
| order by Timestamp desc
```

```kql
// 2. AWS agent sequence (Sentinel AWSCloudTrail): anonymous S3 reads, not-found probes, Cognito sign-up bursts,
//    log mining, and wide enumeration with mass AccessDenied, scored per source IP per hour
AWSCloudTrail
| where TimeGenerated > ago(14d)
| extend RP = tostring(RequestParameters)
| summarize
    AnonS3Reads   = countif(EventSource == "s3.amazonaws.com" and (UserIdentityAccountId == "anonymous" or UserIdentityType == "AWSAccount" and UserIdentityPrincipalid == "anonymous") and EventName in ("GetObject","ListObjects","ListObjectsV2","HeadObject","GetBucketAcl")),
    NotFoundProbes= countif(RP has_any ("zzz_nonexistent","Notexist-xyz","zzz-nonexistent")),
    CognitoSignUp = countif(EventSource == "cognito-idp.amazonaws.com" and EventName in ("SignUp","ResendConfirmationCode","ForgotPassword","InitiateAuth","RespondToAuthChallenge")),
    PreSignUpFail = countif(EventSource == "cognito-idp.amazonaws.com" and ErrorMessage has "PreSignUp"),
    LogMining     = countif(EventName == "FilterLogEvents" and RP has "\"limit\":1000"),
    WhoAmI        = countif(EventName == "GetCallerIdentity"),
    Denied        = countif(ErrorCode in ("AccessDenied","AccessDeniedException","UnauthorizedOperation","Client.UnauthorizedOperation")),
    Services      = dcount(EventSource),
    Regions       = dcount(AWSRegion),
    Identities    = make_set(UserIdentityArn, 10),
    UAs           = make_set(UserAgent, 5)
    by SourceIpAddress, bin(TimeGenerated, 1h)
| extend Score = iff(AnonS3Reads > 20, 1, 0) + iff(NotFoundProbes > 0, 2, 0) + iff(CognitoSignUp > 10, 1, 0) + iff(PreSignUpFail > 3, 1, 0)
               + iff(LogMining > 5, 2, 0) + iff(WhoAmI > 0 and Services >= 8, 1, 0) + iff(Denied > 50, 1, 0) + iff(Regions >= 4, 1, 0)
| where Score >= 3
| order by Score desc, Denied desc
```

```kql
// 3. Instance / task role credentials used from outside AWS (Wiz "EC2 Instance Credentials Used Outside Of AWS"; Datadog "long-term key from unexpected IPs")
//    Instance-profile sessions have an i-xxxxxxxx session name; source IPs should be AWS-owned or VPC endpoints
AWSCloudTrail
| where TimeGenerated > ago(14d)
| where UserIdentityType == "AssumedRole" and UserIdentityArn matches regex @":assumed-role/[^/]+/i-[0-9a-f]{8,17}$"
| where SourceIpAddress !endswith ".amazonaws.com" and SourceIpAddress !startswith "AWS Internal"
| where not(ipv4_is_private(SourceIpAddress))
| summarize Calls=count(), Events=make_set(EventName, 30), Denied=countif(isnotempty(ErrorCode)), UAs=make_set(UserAgent, 5), First=min(TimeGenerated), Last=max(TimeGenerated) by UserIdentityArn, SourceIpAddress
| order by Calls desc
// Validate each SourceIpAddress against your EC2 public / Elastic IPs and the AWS ip-ranges.json before escalating
```

## CrowdStrike Falcon (CQL)

```
// 1. Falcon endpoint: new local accounts and files named by agentic frameworks, and ARTEX-intrusion web shell names
#event_simpleName=/^(UserAccountCreated|UserAccountAddedToGroup)$/
| UserName=/(^|[^a-z])(pentest[-_]?(probe|recon|i\d{4,7}|[a-z0-9]{6,10})|csai[-_]|artex|artx[-_]|artexprobe|reconprobe|i\d{3,7}[-_]?(probe|canary))/i
| table([@timestamp, ComputerName, #event_simpleName, UserName, DomainName, GroupRid])
```

```
// 2. Falcon endpoint: probe files, ARTEX release archives, beacons and web shells written to disk
#event_simpleName=/Written$/
| TargetFileName=/(artex-probe-\d{3,6}|artex-\d+\.\d+\.\d+-(linux|darwin|windows)-(amd64|arm64)\.zip|cl1217\.jsp|f1219a\.jsp|z1219\.jsp|beacon_linux_amd64|wisp-agent)$/i
| table([@timestamp, ComputerName, #event_simpleName, TargetFileName, ContextBaseFileName, UserName])
```

```
// 3. NG-SIEM (AWS CloudTrail / Entra audit): self-labelled cloud identities and resources, and the AWS agent sequence
#Vendor=/aws|microsoft/i
| coalesce([Vendor.requestParameters.userName, Vendor.requestParameters.roleName, Vendor.requestParameters.roleSessionName, Vendor.requestParameters.functionName, Vendor.requestParameters.bucketName, Vendor.userIdentity.arn, user.name, Vendor.targetResources[0].userPrincipalName, Vendor.targetResources[0].displayName], as=resname)
| coalesce([event.action, Vendor.eventName, Vendor.operationName], as=action)
| resname=/(^|[^a-z])(pentest[-_]?(probe|recon|i\d{4,7}|role|[a-z0-9]{6,10})|csai[-_]|artex|artx[-_]|artexprobe|reconprobe|i\d{3,7}[-_]?(probe|canary))/i
   OR Vendor.requestParameters.key=/(zzz_nonexistent|Notexist-xyz)/
   OR (action="FilterLogEvents" AND Vendor.requestParameters.limit=1000)
| default(field=[source.ip], value="-")
| groupBy([resname, action, source.ip, #Vendor], function=[count(as=Events), min(@timestamp, as=First), max(@timestamp, as=Last)])
| sort(Events, order=desc)
```

## Notes

These names come from the agents' own prompts (they tag what they create so they can clean up or track step counters), so they are cheap to change. Still, Wiz, Bitrise, GTIG and Datadog all saw them in live intrusions, and they are among the few signals that survive IP rotation. A `pentest-*` or `csai-*` resource that nobody in your change log created is an incident until proven otherwise: identify the creating principal, then treat every secret that principal could read as exposed. Query 2 is a score, not a verdict: tune the thresholds to your own CloudTrail volume. The CrowdStrike NG-SIEM field paths for CloudTrail depend on your parser and are unverified.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
