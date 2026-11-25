# CD-046 · ARTEX Agentic-Attack Infrastructure Sweep (Wiz "Agentic attacks in the wild" IPs + Datadog / Corelight corroboration)
| | |
|---|---|
| **Hunts for** | (1) Any contact, sign-in or cloud API call to or from the 74 IPs Wiz published for agentic (ARTEX and related) intrusions, plus 10 Datadog and 1 Corelight ARTEX addresses, tagged by role; (2) which of those touches **succeeded**, because Wiz warns a match on the spraying set may only be a failed attempt; (3) the blast radius: everything an identity did after it first succeeded from one of these IPs, from any address. |
| **Threat / CVE** | Wiz Research and CIRT, **"Agentic attacks in the wild"** (Nov 2026): ARTEX-Harvester (stolen VCS credentials → CI workload-identity abuse → secrets and Terraform state dumped → Kubernetes cluster-admin), the anonymised "Both Sides" CyberStrikeAI case (7 EKS clusters, Jenkins RCE, `ld.so.preload` rootkit), and Black October against AI developer platforms. Traffic rotates through residential/ISP proxy pools and cheap VPS hosts. Wiz advisory `wiz-adv-2026-212`. No CVE. |
| **MITRE ATT&CK** | T1078.004 Cloud Accounts, T1110.003 Password Spraying, T1090.002 External Proxy, T1552.001 Credentials In Files, T1528 Steal Application Access Token |
| **Category** | Initial Access / Credential Access (IOC sweep) |
| **First published** | 2026-11-25 (ARTEX special, from the Wiz report plus open-source reporting) |

## Indicators

Source of truth: [`wiz-research-iocs/reports/agentic_attacks_in_the_wild_iocs.csv`](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/agentic_attacks_in_the_wild_iocs.csv) (74 IPs, pulled 2026-11-25). Wiz's Black October list (200+ IOCs) is in `reports/black_october_iocs.csv` in the same repo and is not included here.

| Role | Count | Observed (2026) | IPs |
|---|---|---|---|
| Wiz: used with stolen cloud / identity credentials | 57 | Sep 30 – Nov 23 (per-provider windows in the Wiz table) | 192.236.187.90, 104.223.50.72, 107.172.5.167, 107.173.104.66, 130.94.102.111, 130.94.103.64, 130.94.109.218, 38.60.171.222, 172.86.80.80, 172.86.82.159, 172.86.82.160, 172.86.82.161, 172.86.82.163, 172.86.82.164, 172.86.82.178, 172.86.82.179, 118.107.19.99, 137.220.202.200, 134.122.173.40, 134.122.163.240, 143.92.37.131, 68.166.169.20, 134.222.209.136, 129.80.215.35, 129.121.162.36, 43.172.40.251, 129.226.56.74, 142.86.89.21, 168.143.104.44, 103.27.80.145, 216.203.20.186, 66.179.31.32, 8.208.101.210, 8.222.148.117, 47.79.40.236, 47.84.82.39, 47.79.89.122, 58.243.42.153, 123.116.51.114, 5.181.181.168, 37.77.150.119, 45.76.225.196, 72.57.131.24, 149.255.35.138, 154.86.0.28, 157.22.126.128, 162.251.248.190, 166.0.23.89, 180.178.51.150, 187.77.250.192, 194.59.30.231, 199.19.77.84, 45.199.130.250, 111.223.247.165, 45.38.20.153, 85.193.69.250, 82.29.53.185 |
| Wiz: ARTEX operator host | 3 | Late Oct – Nov 1 | 68.68.250.114, 192.238.246.157, 104.207.150.173 |
| Wiz: stolen credentials + wide probing / password spraying (a match may be a failed attempt) | 14 | Oct 31 – Nov 23 | 2.26.225.135, 109.238.87.4, 111.223.247.202, 130.94.108.151, 161.77.116.139, 185.87.121.140, 45.199.130.245, 2.26.226.17, 2.26.225.235, 134.122.173.60, 130.94.103.197, 76.13.169.197, 82.29.131.60, 130.94.35.151 |
| Datadog Security Labs: ARTEX activity in AWS (NetLab Global, Zeofast, TTNet and others) | 10 | Reported Nov 2026 | 169.128.55.214, 154.64.252.77, 154.36.136.197, 154.36.136.23, 102.216.154.102, 82.158.88.233, 88.229.22.232, 103.54.154.40, 103.54.154.32, 45.145.228.25 |
| Corelight: ARTEX host with open directory of `beacon_linux_amd64` builds, port 8299 | 1 | Reported Nov 2026 | 108.165.147.226 |

**Intel MCP `ip_lookup` on the operator hosts:** 104.207.150.173 is AS20473 Vultr, datacenter, PTR `vultrusercontent.com`; 68.68.250.114 is AS1054 Zont LLC (US); 192.238.246.157 is AS138995 Antbox Networks (HK-registered, geolocates US); 108.165.147.226 is AS149440 Evoxt (MY, geolocates HK). None is on Spamhaus DROP. AbuseIPDB and Shodan were **not available** (paid tier), so reputation is unchecked; the verdict rests on Wiz, Datadog and Corelight reporting: **suspicious to confirmed malicious infrastructure for this activity window, high confidence in attribution to agentic campaigns, low confidence that the addresses stay hostile** (many are rotating proxy or VPS exits that get reassigned).

## Microsoft Defender XDR / Sentinel (KQL)

```kql
// 1. IOC sweep across endpoint, identity, cloud, firewall and web logs, tagged by role, with a success flag
let artexIOC = datatable(IP:string, Role:string) [
  "192.236.187.90", "Wiz: stolen-credential use",
  "104.223.50.72", "Wiz: stolen-credential use",
  "107.172.5.167", "Wiz: stolen-credential use",
  "107.173.104.66", "Wiz: stolen-credential use",
  "130.94.102.111", "Wiz: stolen-credential use",
  "130.94.103.64", "Wiz: stolen-credential use",
  "130.94.109.218", "Wiz: stolen-credential use",
  "38.60.171.222", "Wiz: stolen-credential use",
  "172.86.80.80", "Wiz: stolen-credential use",
  "172.86.82.159", "Wiz: stolen-credential use",
  "172.86.82.160", "Wiz: stolen-credential use",
  "172.86.82.161", "Wiz: stolen-credential use",
  "172.86.82.163", "Wiz: stolen-credential use",
  "172.86.82.164", "Wiz: stolen-credential use",
  "172.86.82.178", "Wiz: stolen-credential use",
  "172.86.82.179", "Wiz: stolen-credential use",
  "118.107.19.99", "Wiz: stolen-credential use",
  "137.220.202.200", "Wiz: stolen-credential use",
  "134.122.173.40", "Wiz: stolen-credential use",
  "134.122.163.240", "Wiz: stolen-credential use",
  "143.92.37.131", "Wiz: stolen-credential use",
  "68.166.169.20", "Wiz: stolen-credential use",
  "134.222.209.136", "Wiz: stolen-credential use",
  "129.80.215.35", "Wiz: stolen-credential use",
  "129.121.162.36", "Wiz: stolen-credential use",
  "43.172.40.251", "Wiz: stolen-credential use",
  "129.226.56.74", "Wiz: stolen-credential use",
  "142.86.89.21", "Wiz: stolen-credential use",
  "168.143.104.44", "Wiz: stolen-credential use",
  "103.27.80.145", "Wiz: stolen-credential use",
  "216.203.20.186", "Wiz: stolen-credential use",
  "66.179.31.32", "Wiz: stolen-credential use",
  "8.208.101.210", "Wiz: stolen-credential use",
  "8.222.148.117", "Wiz: stolen-credential use",
  "47.79.40.236", "Wiz: stolen-credential use",
  "47.84.82.39", "Wiz: stolen-credential use",
  "47.79.89.122", "Wiz: stolen-credential use",
  "58.243.42.153", "Wiz: stolen-credential use",
  "123.116.51.114", "Wiz: stolen-credential use",
  "5.181.181.168", "Wiz: stolen-credential use",
  "37.77.150.119", "Wiz: stolen-credential use",
  "45.76.225.196", "Wiz: stolen-credential use",
  "72.57.131.24", "Wiz: stolen-credential use",
  "149.255.35.138", "Wiz: stolen-credential use",
  "154.86.0.28", "Wiz: stolen-credential use",
  "157.22.126.128", "Wiz: stolen-credential use",
  "162.251.248.190", "Wiz: stolen-credential use",
  "166.0.23.89", "Wiz: stolen-credential use",
  "180.178.51.150", "Wiz: stolen-credential use",
  "187.77.250.192", "Wiz: stolen-credential use",
  "194.59.30.231", "Wiz: stolen-credential use",
  "199.19.77.84", "Wiz: stolen-credential use",
  "45.199.130.250", "Wiz: stolen-credential use",
  "111.223.247.165", "Wiz: stolen-credential use",
  "45.38.20.153", "Wiz: stolen-credential use",
  "85.193.69.250", "Wiz: stolen-credential use",
  "82.29.53.185", "Wiz: stolen-credential use",
  "68.68.250.114", "Wiz: ARTEX operator host",
  "192.238.246.157", "Wiz: ARTEX operator host",
  "104.207.150.173", "Wiz: ARTEX operator host",
  "2.26.225.135", "Wiz: stolen creds + spraying",
  "109.238.87.4", "Wiz: stolen creds + spraying",
  "111.223.247.202", "Wiz: stolen creds + spraying",
  "130.94.108.151", "Wiz: stolen creds + spraying",
  "161.77.116.139", "Wiz: stolen creds + spraying",
  "185.87.121.140", "Wiz: stolen creds + spraying",
  "45.199.130.245", "Wiz: stolen creds + spraying",
  "2.26.226.17", "Wiz: stolen creds + spraying",
  "2.26.225.235", "Wiz: stolen creds + spraying",
  "134.122.173.60", "Wiz: stolen creds + spraying",
  "130.94.103.197", "Wiz: stolen creds + spraying",
  "76.13.169.197", "Wiz: stolen creds + spraying",
  "82.29.131.60", "Wiz: stolen creds + spraying",
  "130.94.35.151", "Wiz: stolen creds + spraying",
  "169.128.55.214", "Datadog: ARTEX AWS activity",
  "154.64.252.77", "Datadog: ARTEX AWS activity",
  "154.36.136.197", "Datadog: ARTEX AWS activity",
  "154.36.136.23", "Datadog: ARTEX AWS activity",
  "102.216.154.102", "Datadog: ARTEX AWS activity",
  "82.158.88.233", "Datadog: ARTEX AWS activity",
  "88.229.22.232", "Datadog: ARTEX AWS activity",
  "103.54.154.40", "Datadog: ARTEX AWS activity",
  "103.54.154.32", "Datadog: ARTEX AWS activity",
  "45.145.228.25", "Datadog: ARTEX AWS activity",
  "108.165.147.226", "Corelight: ARTEX open-dir host"
];
let ipList = toscalar(artexIOC | summarize make_list(IP));
union isfuzzy=true
 (DeviceNetworkEvents | where Timestamp > ago(60d) | where RemoteIP in (ipList)
    | project Timestamp, Source="DeviceNetworkEvents", IP=RemoteIP, Who=DeviceName, Detail=strcat(ActionType, " ", InitiatingProcessFileName, ":", RemotePort), Success=ActionType in ("ConnectionSuccess","InboundConnectionAccepted")),
 (EntraIdSignInEvents | where Timestamp > ago(60d) | where IPAddress in (ipList)
    | project Timestamp, Source="EntraIdSignInEvents", IP=IPAddress, Who=AccountUpn, Detail=strcat(Application, " ErrorCode=", ErrorCode, " ", UserAgent), Success=ErrorCode == 0),
 (CloudAppEvents | where Timestamp > ago(60d) | where IPAddress in (ipList)
    | project Timestamp, Source="CloudAppEvents", IP=IPAddress, Who=AccountDisplayName, Detail=strcat(Application, " ", ActionType, " ", UserAgent), Success=true),
 (SigninLogs | where TimeGenerated > ago(60d) | where IPAddress in (ipList)
    | project Timestamp=TimeGenerated, Source="SigninLogs", IP=IPAddress, Who=UserPrincipalName, Detail=strcat(AppDisplayName, " ", ResultType, " ", UserAgent), Success=ResultType == "0"),
 (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(60d) | where IPAddress in (ipList)
    | project Timestamp=TimeGenerated, Source="AADNonInteractive", IP=IPAddress, Who=UserPrincipalName, Detail=strcat(AppDisplayName, " ", ResultType, " ", UserAgent), Success=ResultType == "0"),
 (MicrosoftGraphActivityLogs | where TimeGenerated > ago(60d) | where IPAddress in (ipList)
    | project Timestamp=TimeGenerated, Source="GraphActivity", IP=IPAddress, Who=coalesce(UserId, ServicePrincipalId, AppId), Detail=strcat(RequestMethod, " ", RequestUri), Success=ResponseStatusCode between (200 .. 299)),
 (AWSCloudTrail | where TimeGenerated > ago(60d) | where SourceIpAddress in (ipList)
    | project Timestamp=TimeGenerated, Source="AWSCloudTrail", IP=SourceIpAddress, Who=UserIdentityArn, Detail=strcat(EventSource, " ", EventName, " ", ErrorCode, " ", UserAgent), Success=isempty(ErrorCode)),
 (AzureActivity | where TimeGenerated > ago(60d) | where CallerIpAddress in (ipList)
    | project Timestamp=TimeGenerated, Source="AzureActivity", IP=CallerIpAddress, Who=Caller, Detail=OperationNameValue, Success=ActivityStatusValue in ("Success","Succeeded")),
 (CommonSecurityLog | where TimeGenerated > ago(60d) | where SourceIP in (ipList) or DestinationIP in (ipList)
    | project Timestamp=TimeGenerated, Source="CommonSecurityLog", IP=iff(SourceIP in (ipList), SourceIP, DestinationIP), Who=DeviceName, Detail=strcat(DeviceVendor, " ", DeviceAction, " ", RequestURL), Success=DeviceAction !in~ ("deny","drop","block","blocked","reset")),
 (W3CIISLog | where TimeGenerated > ago(60d) | where cIP in (ipList)
    | project Timestamp=TimeGenerated, Source="W3CIISLog", IP=cIP, Who=sSiteName, Detail=strcat(csMethod, " ", csUriStem, " ", scStatus, " ", csUserAgent), Success=toint(scStatus) < 400)
| join kind=leftouter artexIOC on IP
| summarize Events=count(), Successes=countif(Success), First=min(Timestamp), Last=max(Timestamp), Identities=make_set(Who, 25), Sample=take_any(Detail) by IP, Role, Source
| order by Successes desc, Events desc
```

```kql
// 2. Blast radius: identities that SUCCEEDED from an ARTEX IP, then everything they did afterwards from ANY IP
let ipList = dynamic(["192.236.187.90","104.223.50.72","107.172.5.167","107.173.104.66","130.94.102.111","130.94.103.64","130.94.109.218","38.60.171.222","172.86.80.80","172.86.82.159","172.86.82.160","172.86.82.161","172.86.82.163","172.86.82.164","172.86.82.178","172.86.82.179","118.107.19.99","137.220.202.200","134.122.173.40","134.122.163.240","143.92.37.131","68.166.169.20","134.222.209.136","129.80.215.35","129.121.162.36","43.172.40.251","129.226.56.74","142.86.89.21","168.143.104.44","103.27.80.145","216.203.20.186","66.179.31.32","8.208.101.210","8.222.148.117","47.79.40.236","47.84.82.39","47.79.89.122","58.243.42.153","123.116.51.114","5.181.181.168","37.77.150.119","45.76.225.196","72.57.131.24","149.255.35.138","154.86.0.28","157.22.126.128","162.251.248.190","166.0.23.89","180.178.51.150","187.77.250.192","194.59.30.231","199.19.77.84","45.199.130.250","111.223.247.165","45.38.20.153","85.193.69.250","82.29.53.185","68.68.250.114","192.238.246.157","104.207.150.173","2.26.225.135","109.238.87.4","111.223.247.202","130.94.108.151","161.77.116.139","185.87.121.140","45.199.130.245","2.26.226.17","2.26.225.235","134.122.173.60","130.94.103.197","76.13.169.197","82.29.131.60","130.94.35.151","169.128.55.214","154.64.252.77","154.36.136.197","154.36.136.23","102.216.154.102","82.158.88.233","88.229.22.232","103.54.154.40","103.54.154.32","45.145.228.25","108.165.147.226"]);
let firstHit = union isfuzzy=true
 (SigninLogs | where TimeGenerated > ago(60d) | where IPAddress in (ipList) and ResultType == "0" | project Who=UserPrincipalName, T=TimeGenerated),
 (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(60d) | where IPAddress in (ipList) and ResultType == "0" | project Who=UserPrincipalName, T=TimeGenerated),
 (AWSCloudTrail | where TimeGenerated > ago(60d) | where SourceIpAddress in (ipList) and isempty(ErrorCode) | project Who=UserIdentityArn, T=TimeGenerated)
| summarize FirstHit=min(T) by Who;
union isfuzzy=true
 (AuditLogs | where TimeGenerated > ago(60d) | extend Who=tostring(InitiatedBy.user.userPrincipalName)
    | project TimeGenerated, Source="AuditLogs", Who, Action=OperationName, IP=tostring(InitiatedBy.user.ipAddress)),
 (SigninLogs | where TimeGenerated > ago(60d) | where ResultType == "0"
    | project TimeGenerated, Source="SigninLogs", Who=UserPrincipalName, Action=strcat("SignIn ", AppDisplayName), IP=IPAddress),
 (AWSCloudTrail | where TimeGenerated > ago(60d) | where isempty(ErrorCode)
    | project TimeGenerated, Source="AWSCloudTrail", Who=UserIdentityArn, Action=strcat(EventSource, " ", EventName), IP=SourceIpAddress)
| join kind=inner firstHit on Who
| where TimeGenerated >= FirstHit
| summarize Actions=count(), DistinctActions=make_set(Action, 50), IPs=make_set(IP, 25), Last=max(TimeGenerated) by Who, FirstHit, Source
| order by FirstHit asc
```

## CrowdStrike Falcon (CQL)

```
// 1. Falcon endpoint: hosts talking to ARTEX infrastructure (network events carry no host name, so join aidmaster)
#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4)$/
| in(field="RemoteAddressIP4", values=["192.236.187.90","104.223.50.72","107.172.5.167","107.173.104.66","130.94.102.111","130.94.103.64","130.94.109.218","38.60.171.222","172.86.80.80","172.86.82.159","172.86.82.160","172.86.82.161","172.86.82.163","172.86.82.164","172.86.82.178","172.86.82.179","118.107.19.99","137.220.202.200","134.122.173.40","134.122.163.240","143.92.37.131","68.166.169.20","134.222.209.136","129.80.215.35","129.121.162.36","43.172.40.251","129.226.56.74","142.86.89.21","168.143.104.44","103.27.80.145","216.203.20.186","66.179.31.32","8.208.101.210","8.222.148.117","47.79.40.236","47.84.82.39","47.79.89.122","58.243.42.153","123.116.51.114","5.181.181.168","37.77.150.119","45.76.225.196","72.57.131.24","149.255.35.138","154.86.0.28","157.22.126.128","162.251.248.190","166.0.23.89","180.178.51.150","187.77.250.192","194.59.30.231","199.19.77.84","45.199.130.250","111.223.247.165","45.38.20.153","85.193.69.250","82.29.53.185","68.68.250.114","192.238.246.157","104.207.150.173","2.26.225.135","109.238.87.4","111.223.247.202","130.94.108.151","161.77.116.139","185.87.121.140","45.199.130.245","2.26.226.17","2.26.225.235","134.122.173.60","130.94.103.197","76.13.169.197","82.29.131.60","130.94.35.151","169.128.55.214","154.64.252.77","154.36.136.197","154.36.136.23","102.216.154.102","82.158.88.233","88.229.22.232","103.54.154.40","103.54.154.32","45.145.228.25","108.165.147.226"])
| join(query={#data_source_name=aidmaster | groupBy([aid], function=selectLast([ComputerName]))}, field=[aid], include=[ComputerName])
| groupBy([ComputerName, RemoteAddressIP4, RemotePort, #event_simpleName], function=[count(as=Events), min(@timestamp, as=First), max(@timestamp, as=Last)])
| sort(Events, order=desc)
```

```
// 2. NG-SIEM: sign-ins, API calls and firewall/proxy events from ARTEX infrastructure in third-party logs
coalesce([source.ip, Vendor.sourceIPAddress, Vendor.callerIpAddress, Vendor.properties.ipAddress], as=srcip)
| in(field="srcip", values=["192.236.187.90","104.223.50.72","107.172.5.167","107.173.104.66","130.94.102.111","130.94.103.64","130.94.109.218","38.60.171.222","172.86.80.80","172.86.82.159","172.86.82.160","172.86.82.161","172.86.82.163","172.86.82.164","172.86.82.178","172.86.82.179","118.107.19.99","137.220.202.200","134.122.173.40","134.122.163.240","143.92.37.131","68.166.169.20","134.222.209.136","129.80.215.35","129.121.162.36","43.172.40.251","129.226.56.74","142.86.89.21","168.143.104.44","103.27.80.145","216.203.20.186","66.179.31.32","8.208.101.210","8.222.148.117","47.79.40.236","47.84.82.39","47.79.89.122","58.243.42.153","123.116.51.114","5.181.181.168","37.77.150.119","45.76.225.196","72.57.131.24","149.255.35.138","154.86.0.28","157.22.126.128","162.251.248.190","166.0.23.89","180.178.51.150","187.77.250.192","194.59.30.231","199.19.77.84","45.199.130.250","111.223.247.165","45.38.20.153","85.193.69.250","82.29.53.185","68.68.250.114","192.238.246.157","104.207.150.173","2.26.225.135","109.238.87.4","111.223.247.202","130.94.108.151","161.77.116.139","185.87.121.140","45.199.130.245","2.26.226.17","2.26.225.235","134.122.173.60","130.94.103.197","76.13.169.197","82.29.131.60","130.94.35.151","169.128.55.214","154.64.252.77","154.36.136.197","154.36.136.23","102.216.154.102","82.158.88.233","88.229.22.232","103.54.154.40","103.54.154.32","45.145.228.25","108.165.147.226"])
| case {
    in(field="srcip", values=["68.68.250.114","192.238.246.157","104.207.150.173","108.165.147.226"]) | Role := "ARTEX operator host";
    in(field="srcip", values=["2.26.225.135","109.238.87.4","111.223.247.202","130.94.108.151","161.77.116.139","185.87.121.140","45.199.130.245","2.26.226.17","2.26.225.235","134.122.173.60","130.94.103.197","76.13.169.197","82.29.131.60","130.94.35.151"]) | Role := "Stolen creds + spraying (may be failed)";
    * | Role := "Stolen-credential use / ARTEX activity";
  }
| default(field=[user.name, event.action, event.outcome], value="-")
| groupBy([srcip, Role, #Vendor, event.outcome], function=[count(as=Events), collect([user.name, event.action], limit=25), min(@timestamp, as=First), max(@timestamp, as=Last)])
| sort(Events, order=desc)
```

## Notes

Wiz and its CIRT are explicit that IP blocking is a weak control against proxy-rotating agents, and that a hit on the spraying set may be a failed attempt. Use this sweep to find **successful** use first (query 2 in each platform), then rotate every credential, token and key that identity could reach: CI/CD secrets, Terraform state, cloud keys, Kubernetes service-account tokens, AI provider API keys. The lists go stale quickly: the newest Wiz addresses end Nov 23, so keep lookbacks to 60 days and re-check before blocking. Pair with CD-045 (user agents) and CD-047 (behaviour), which survive IP rotation.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
