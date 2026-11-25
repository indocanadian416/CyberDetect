# CD-045 · ARTEX and Agentic Offensive Framework User Agents (artex-pentest, artex-audit, norma/0.4, ARTeX-authorized-pentest and related)
| | |
|---|---|
| **Hunts for** | (1) HTTP and API requests that carry a user agent naming ARTEX or a sibling agentic framework (CyberStrikeAI, HexStrike, PentAGI), in Entra ID sign-ins, Microsoft Graph, M365 / Defender for Cloud Apps, AWS CloudTrail, IIS, proxies and WAFs; (2) the lower-fidelity fingerprints of the ARTEX actor: a Chrome user agent with no `AppleWebKit` token, and the aws-cli / Boto3 build seen on the same Linux kernel; (3) what an identity changed in Entra within 24 hours of a *successful* sign-in that carried one of these user agents; (4) on Falcon hosts, command lines that set these strings (an agent shell running on a compromised box). |
| **Threat / CVE** | **ARTEX**: open-source, Go-based, multi-agent LLM pentest and C2 framework (public since July 2026, hundreds of forks), used by unrelated operators including China-aligned **Storm-0940** (ConnectWise supply-chain abuse, 2,250+ M365 tenants targeted), a financially motivated ring against South Korean finance, and the campaigns in **Wiz's "Agentic attacks in the wild" (ARTEX-Harvester, "Both Sides", Black October)**. Agents label their own traffic. No CVE. |
| **MITRE ATT&CK** | T1595.002 Vulnerability Scanning, T1110.003 Password Spraying, T1078.004 Cloud Accounts, T1550.001 Application Access Token, T1071.001 Web Protocols |
| **Category** | Reconnaissance / Initial Access |
| **First published** | 2026-11-25 (ARTEX special, from the Wiz report plus open-source reporting) |

## User agents in this hunt

| User agent (verbatim) | Fidelity | Source |
|---|---|---|
| `artex-pentest/1.0`, `artex-audit/1.0`, `artex-readonly/1.0`, `artex-verify/1.0`, `artex-spawn/1`, `ARTEX-worker/1.0`, `artex-i21861-canary` | High | Datadog Security Labs (AWS intrusions); also Corelight, ThreatDefence |
| `Mozilla/5.0 ARTeX`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ARTeX-authorized-pentest`, `Mozilla/5.0 (X11; Linux x86_64) artex-verify/1.0` | High | Datadog Security Labs |
| `artex-enrich/1.0` (asset enrichment, one GET to `/` per site), `ArtEx` | High | WorkOS via StepSecurity, Elastic, Intrinsec |
| `artex-selfupdate` (ARTEX host checking GitHub releases; shows in *your* egress logs only if ARTEX runs inside your estate) | High | Intrinsec, CTI Academy, Corelight |
| `norma/0.4` (hard-coded in ARTEX's agent SDK web-fetch tool; every fork checked still sends it) | Medium (other norma-based agents send it too) | Bitrise, pentestit, Elastic, StepSecurity |
| `Mozilla/5.0 (spa-api-recon…` (ARTEX api-recon skill scripts) | High | Corelight |
| `pentest-recon` | High | Wiz (this report) |
| `ReconProbe/1.0` | High | Corelight, from Wiz reporting |
| `azure-toolkit/1.0` | High (Storm-0940 sign-ins and Graph calls) | Corelight, Microsoft |
| `CyberStrikeAI/…`, `CyberStrikeAI-WebShell/…` | High (framework behind Wiz's "Both Sides" case) | Corelight |
| `HexStrike-BrowserAgent/…`, `HexStrike-HTTP-Framework/…`, `Mozilla/5.0 (Compatible Exploit)` | High | Corelight |
| `PentAGI/…` | Medium | Corelight |
| Any UA claiming an "authorized pentest" | Medium | Bitrise incident report |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36` and `… Chrome/120` (no AppleWebKit) | Low | Corelight |
| `aws-cli/1.46.1` or `Boto3/1.43.112` / `1.43.113` on `Linux/6.8.0-147-generic` | Low to medium | Corelight, Wiz ("distinctive boto3 build") |

The public ARTEX code does not send most branded strings (ThreatDefence source review); operators add them through the opt-in scanner-UA setting or their own prompts. Expect renamed builds to drop them, so a miss here means little. A hit is a strong lead.

## Microsoft Defender XDR / Sentinel (KQL)

```kql
// 1. Branded ARTEX / agentic-framework user agents across identity, cloud, web and endpoint HTTP telemetry
//    union isfuzzy=true skips tables you do not have (Defender-only tenants keep the first three)
let artexUA = @"(?i)(artex|artx-|norma/0\.4|spa-api-recon|reconprobe/|pentest-recon|azure-toolkit/1\.0|cyberstrikeai|hexstrike-|pentagi/|\(compatible exploit\)|authori[sz]ed[-_ +]?pentest)";
union isfuzzy=true
 (EntraIdSignInEvents | where Timestamp > ago(30d) | where UserAgent matches regex artexUA
    | project Timestamp, Source="EntraIdSignInEvents", UA=UserAgent, IP=IPAddress, Who=AccountUpn, Detail=strcat(Application, " ErrorCode=", ErrorCode)),
 (CloudAppEvents | where Timestamp > ago(30d) | where UserAgent matches regex artexUA
    | project Timestamp, Source="CloudAppEvents", UA=UserAgent, IP=IPAddress, Who=AccountDisplayName, Detail=strcat(Application, " ", ActionType)),
 (DeviceNetworkEvents | where Timestamp > ago(30d) | where ActionType == "HttpConnectionInspected"
    | extend AF = parse_json(AdditionalFields) | extend UA = tostring(AF.user_agent) | where UA matches regex artexUA
    | project Timestamp, Source="DeviceNetworkEvents", UA, IP=RemoteIP, Who=DeviceName, Detail=strcat(tostring(AF.method), " ", tostring(AF.host), tostring(AF.uri))),
 (SigninLogs | where TimeGenerated > ago(30d) | where UserAgent matches regex artexUA
    | project Timestamp=TimeGenerated, Source="SigninLogs", UA=UserAgent, IP=IPAddress, Who=UserPrincipalName, Detail=strcat(AppDisplayName, " ", ResultType)),
 (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(30d) | where UserAgent matches regex artexUA
    | project Timestamp=TimeGenerated, Source="AADNonInteractiveUserSignInLogs", UA=UserAgent, IP=IPAddress, Who=UserPrincipalName, Detail=strcat(AppDisplayName, " ", ResultType)),
 (MicrosoftGraphActivityLogs | where TimeGenerated > ago(30d) | where UserAgent matches regex artexUA
    | project Timestamp=TimeGenerated, Source="MicrosoftGraphActivityLogs", UA=UserAgent, IP=IPAddress, Who=coalesce(UserId, ServicePrincipalId, AppId), Detail=strcat(RequestMethod, " ", RequestUri, " ", ResponseStatusCode)),
 (AWSCloudTrail | where TimeGenerated > ago(30d) | where UserAgent matches regex artexUA
    | project Timestamp=TimeGenerated, Source="AWSCloudTrail", UA=UserAgent, IP=SourceIpAddress, Who=UserIdentityArn, Detail=strcat(EventSource, " ", EventName, " ", ErrorCode)),
 (W3CIISLog | where TimeGenerated > ago(30d) | where csUserAgent matches regex artexUA
    | project Timestamp=TimeGenerated, Source="W3CIISLog", UA=csUserAgent, IP=cIP, Who=sSiteName, Detail=strcat(csMethod, " ", csUriStem, " ", scStatus)),
 (CommonSecurityLog | where TimeGenerated > ago(30d) | where RequestClientApplication matches regex artexUA
    | project Timestamp=TimeGenerated, Source="CommonSecurityLog", UA=RequestClientApplication, IP=SourceIP, Who=DeviceVendor, Detail=strcat(RequestURL, " ", DeviceAction))
| summarize Events=count(), First=min(Timestamp), Last=max(Timestamp), Sources=make_set(Source), IPs=make_set(IP, 25), Identities=make_set(Who, 25), Sample=take_any(Detail) by UA
| order by Events desc
```

```kql
// 2. Lower-fidelity ARTEX-actor fingerprints: Chrome UA with no AppleWebKit token,
//    and the aws-cli / Boto3 build on kernel 6.8.0-147-generic seen in ARTEX AWS intrusions
let fakeChrome = @"^Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) Chrome/(120|124)";
union isfuzzy=true
 (SigninLogs | where TimeGenerated > ago(30d) | where UserAgent matches regex fakeChrome
    | project TimeGenerated, Source="SigninLogs", UserAgent, IP=IPAddress, Who=UserPrincipalName, Result=tostring(ResultType)),
 (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(30d) | where UserAgent matches regex fakeChrome
    | project TimeGenerated, Source="AADNonInteractive", UserAgent, IP=IPAddress, Who=UserPrincipalName, Result=tostring(ResultType)),
 (MicrosoftGraphActivityLogs | where TimeGenerated > ago(30d) | where UserAgent matches regex fakeChrome
    | project TimeGenerated, Source="GraphActivity", UserAgent, IP=IPAddress, Who=coalesce(UserId, AppId), Result=tostring(ResponseStatusCode)),
 (AWSCloudTrail | where TimeGenerated > ago(30d)
    | where UserAgent matches regex fakeChrome
        or (UserAgent matches regex @"(aws-cli/1\.46\.1|Boto3/1\.43\.11[23])" and UserAgent has "6.8.0-147-generic")
    | project TimeGenerated, Source="AWSCloudTrail", UserAgent, IP=SourceIpAddress, Who=UserIdentityArn, Result=strcat(EventName, " ", ErrorCode))
| summarize Events=count(), Identities=make_set(Who, 20), Results=make_set(Result, 25), First=min(TimeGenerated), Last=max(TimeGenerated) by Source, UserAgent, IP
| order by Events desc
```

```kql
// 3. Successful sign-ins that carried an agent UA, and what the same identity changed in Entra within 24h
let artexUA = @"(?i)(artex|artx-|norma/0\.4|spa-api-recon|reconprobe/|pentest-recon|azure-toolkit/1\.0|cyberstrikeai|hexstrike-|pentagi/|\(compatible exploit\)|authori[sz]ed[-_ +]?pentest)";
let hits = union isfuzzy=true
 (SigninLogs | where TimeGenerated > ago(30d) | where ResultType == "0" and UserAgent matches regex artexUA
    | project UPN=UserPrincipalName, IP=IPAddress, UA=UserAgent, LoginTime=TimeGenerated),
 (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(30d) | where ResultType == "0" and UserAgent matches regex artexUA
    | project UPN=UserPrincipalName, IP=IPAddress, UA=UserAgent, LoginTime=TimeGenerated);
AuditLogs
| where TimeGenerated > ago(30d)
| extend UPN = tostring(InitiatedBy.user.userPrincipalName)
| join kind=inner hits on UPN
| where TimeGenerated between (LoginTime .. LoginTime + 24h)
| project TimeGenerated, OperationName, UPN, IP, UA, LoginTime, Target=tostring(TargetResources[0].displayName), Result
| order by TimeGenerated asc
```

## CrowdStrike Falcon (CQL)

```
// 1. NG-SIEM: agent user agents in any ingested third-party log (Entra, M365, CloudTrail, proxy, WAF, web server)
//    Field names differ by parser; coalesce() takes the first one present
coalesce([user_agent.original, Vendor.userAgent, Vendor.UserAgent, Vendor.properties.userAgent, Vendor.http_user_agent], as=ua)
| ua=/(artex|artx-|norma\/0\.4|spa-api-recon|reconprobe\/|pentest-recon|azure-toolkit\/1\.0|cyberstrikeai|hexstrike-|pentagi\/|\(compatible exploit\)|authori[sz]ed[-_ +]?pentest)/i
| default(field=[source.ip, user.name], value="-")
| groupBy([ua, #Vendor], function=[count(as=Events), min(@timestamp, as=First), max(@timestamp, as=Last), collect([source.ip, user.name], limit=25)])
| formatTime("%Y-%m-%d %H:%M", field=First, as=First)
| formatTime("%Y-%m-%d %H:%M", field=Last, as=Last)
| sort(Events, order=desc)
```

```
// 2. NG-SIEM: lower-fidelity fingerprints (Chrome UA without AppleWebKit; aws-cli / Boto3 build on kernel 6.8.0-147-generic)
coalesce([user_agent.original, Vendor.userAgent, Vendor.UserAgent, Vendor.properties.userAgent], as=ua)
| ua=/^Mozilla\/5\.0 \(Windows NT 10\.0; Win64; x64\) Chrome\/(120|124)/ OR ua=/(aws-cli\/1\.46\.1|Boto3\/1\.43\.11[23]).*6\.8\.0-147-generic/
| default(field=[source.ip, user.name], value="-")
| groupBy([ua, source.ip, #Vendor], function=[count(as=Events), collect([user.name], limit=20)])
| sort(Events, order=desc)
```

```
// 3. Falcon endpoint: command lines that set ARTEX / agent user agents (curl -A, python requests, Go tools run by an agent shell)
#event_simpleName=ProcessRollup2
| CommandLine=/(artex-(audit|pentest|readonly|verify|enrich|spawn|selfupdate|i\d+)|ARTEX-worker|ARTeX|norma\/0\.4|spa-api-recon|ReconProbe\/|pentest-recon|azure-toolkit\/1\.0|CyberStrikeAI|HexStrike|PentAGI|authori[sz]ed[-_ ]?pentest)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
```

## Notes

A branded UA at your edge means an agent was pointed at you, not that it got in. Triage by outcome: 2xx responses, `ResultType == "0"` sign-ins and CloudTrail calls with no `ErrorCode` come first, then pivot on the source IP with CD-046 and on any identity with CD-047. Block the high-fidelity strings at the WAF and Conditional Access level as a quick win, but remember that the next renamed fork drops them (Wiz, Elastic). If your own red team or pentest vendor uses ARTEX with the scanner UA enabled, exclude their source ranges rather than the strings. Related: CD-040 (Cairn / spraying), CD-046 (Wiz IP sweep), CD-047 (self-labelled artifacts and cloud behaviour), CD-048 (Kubernetes node escape), CD-049 (ARTEX on your own hosts).

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
