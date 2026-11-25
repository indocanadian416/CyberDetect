# CD-049 · ARTEX Running Inside Your Estate and AI Key / Coding-Assistant Session Harvesting
| | |
|---|---|
| **Hunts for** | (1) ARTEX itself on a host you own (an attacker's foothold turned operator box, an insider, or an unapproved "AI pentest"): the ARTEX binary or release archive, its console on default port **8787**, the `artex-selfupdate` client, the recording-proxy CA `_ca/mitmproxy-ca-cert.pem`, and the console login `POST /api/auth/login`; (2) servers that suddenly talk to the LLM APIs ARTEX operators use (DeepSeek, Zhipu GLM, xAI Grok and resellers) while also running scanners (nuclei, httpx, katana, ffuf, sqlmap); (3) processes reading AI provider keys and AI coding-assistant session histories, which Wiz's "Both Sides" operator harvested from 50 hosts to recover production SSO credentials. |
| **Threat / CVE** | ARTEX (Go agent with embedded Next.js console; default port 8787 per its docker-compose; Shodan held 1,558 exposed consoles on Nov 13 and Censys 1,400+ in early November, per pentestit and Wiz). Wiz: Anthropic API keys harvested from 50 hosts; AI coding-assistant session histories mined for SSO credentials; Black October attackers prioritised AI-provider and cloud keys in environment variables. No CVE. |
| **MITRE ATT&CK** | T1588.002 Tool, T1059 Command and Scripting Interpreter, T1552.001 Credentials In Files, T1552.007 Container API, T1005 Data from Local System, T1071.001 Web Protocols |
| **Category** | Execution / Credential Access |
| **First published** | 2026-11-25 (ARTEX special, from the Wiz report plus open-source reporting) |

## Microsoft Defender XDR / Sentinel (KQL)

```kql
// 1. ARTEX binaries, archives, console port and recording-proxy CA on your own devices
union isfuzzy=true
 (DeviceProcessEvents | where Timestamp > ago(30d)
    | where FileName matches regex @"(?i)^artex(\.exe)?$" or ProcessCommandLine matches regex @"(?i)(\bartex\s+(serve|server|run|task|console)\b|artex-selfupdate|ARTEX_TARGET_USER_AGENT|ARTEX_[A-Z_]+=)"
    | project Timestamp, DeviceName, Signal="ARTEX process", Detail=strcat(AccountName, " ", FolderPath, " ", ProcessCommandLine)),
 (DeviceFileEvents | where Timestamp > ago(30d) | where ActionType == "FileCreated"
    | where FileName matches regex @"(?i)^artex-\d+\.\d+\.\d+-(linux|darwin|windows)-(amd64|arm64)\.zip$"
        or (FileName =~ "mitmproxy-ca-cert.pem" and FolderPath has "_ca")
    | project Timestamp, DeviceName, Signal="ARTEX release / proxy CA file", Detail=strcat(FolderPath, " by ", InitiatingProcessFileName)),
 (DeviceNetworkEvents | where Timestamp > ago(30d)
    | where ActionType == "ListeningConnectionCreated" and LocalPort == 8787
    | project Timestamp, DeviceName, Signal="Listener on 8787 (ARTEX console default)", Detail=strcat(InitiatingProcessFileName, " ", InitiatingProcessCommandLine)),
 (DeviceNetworkEvents | where Timestamp > ago(30d) | where ActionType == "HttpConnectionInspected"
    | extend AF = parse_json(AdditionalFields)
    | where tostring(AF.user_agent) startswith "artex-selfupdate" or (tostring(AF.method) == "POST" and tostring(AF.uri) == "/api/auth/login" and RemotePort == 8787)
    | project Timestamp, DeviceName, Signal="ARTEX self-update / console login", Detail=strcat(tostring(AF.host), tostring(AF.uri), " ", tostring(AF.user_agent)))
| order by Timestamp desc
```

```kql
// 2. Servers calling agent-favoured LLM APIs AND running scanners in the same day (likely an agent operator box)
let llmApis = dynamic(["api.deepseek.com","open.bigmodel.cn","api.z.ai","api.x.ai","api.moonshot.cn","dashscope.aliyuncs.com","api.siliconflow.cn","openrouter.ai","api.anthropic.com","api.openai.com"]);
let scanners = dynamic(["nuclei","httpx","katana","ffuf","sqlmap","subfinder","naabu","dirsearch","gobuster","nmap","masscan","nikto"]);
let llm = DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (llmApis)
| summarize LLMCalls=count(), LLMHosts=make_set(RemoteUrl, 10), LLMProcs=make_set(InitiatingProcessFileName, 10) by DeviceId, DeviceName, Day=bin(Timestamp, 1d);
let scan = DeviceProcessEvents
| where Timestamp > ago(14d)
| where tolower(replace_string(FileName, ".exe", "")) in (scanners)
| summarize ScanRuns=count(), Tools=make_set(FileName, 15) by DeviceId, Day=bin(Timestamp, 1d);
llm
| join kind=inner scan on DeviceId, Day
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, DeviceType, OSPlatform) by DeviceId) on DeviceId
| where DeviceType != "Workstation" or isempty(DeviceType)     // servers and containers first; drop this line to include laptops
| project Day, DeviceName, OSPlatform, DeviceType, LLMCalls, LLMHosts, LLMProcs, ScanRuns, Tools
| order by Day desc
```

```kql
// 3. AI provider keys and AI coding-assistant session histories read by processes that are not the assistant itself
let aiPaths = @"(?i)(/\.claude/|\\\.claude\\|\.claude\.json|/\.codex/|\\\.codex\\|/\.gemini/|\\\.gemini\\|/\.cursor/|\\\.cursor\\|/\.aider|/\.continue/|/\.config/github-copilot|\\github-copilot\\|/\.anthropic|/\.openai|/\.config/openai)";
let keyPattern = @"(?i)(ANTHROPIC_API_KEY|OPENAI_API_KEY|DEEPSEEK_API_KEY|sk-ant-|GEMINI_API_KEY)";
union isfuzzy=true
 (DeviceProcessEvents | where Timestamp > ago(30d)
    | where ProcessCommandLine matches regex aiPaths or ProcessCommandLine matches regex keyPattern
    | where FileName in~ ("cat","tar","zip","7z","grep","rg","find","base64","curl","wget","scp","rsync","python","python3","powershell.exe","pwsh","cmd.exe","bash","sh","strings","xxd")
    | where InitiatingProcessFileName !in~ ("claude","codex","gemini","cursor","code","node")   // tune: the assistants themselves
    | project Timestamp, DeviceName, AccountName, Signal="AI session / key read", Detail=strcat(InitiatingProcessFileName, " > ", ProcessCommandLine)),
 (DeviceProcessEvents | where Timestamp > ago(30d)
    | where ProcessCommandLine matches regex @"(?i)(/proc/\d+/environ|/proc/\*/environ|printenv|\benv\b\s*\|)" and ProcessCommandLine matches regex @"(?i)(api_key|anthropic|openai|aws_secret|token)"
    | project Timestamp, DeviceName, AccountName, Signal="Environment secret dump", Detail=strcat(InitiatingProcessFileName, " > ", ProcessCommandLine))
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
// 1. ARTEX binary, self-update client, env vars, release archives and console listener on Falcon hosts
#event_simpleName=ProcessRollup2
| FileName=/^artex(\.exe)?$/i OR CommandLine=/(\bartex\s+(serve|server|run|task|console)\b|artex-selfupdate|ARTEX_TARGET_USER_AGENT|ARTEX_[A-Z_]+=)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, ImageFileName, CommandLine], limit=1000)
```

```
// 2. Listener on 8787 (ARTEX console default) and ARTEX archive / mitmproxy CA written to disk
#event_simpleName=/^(NetworkListenIP4|NetworkListenIP6)$/ LocalPort=8787
| join(query={#data_source_name=aidmaster | groupBy([aid], function=selectLast([ComputerName]))}, field=[aid], include=[ComputerName])
| table([@timestamp, ComputerName, LocalAddressIP4, LocalPort, ContextProcessId])
// Run separately:
// #event_simpleName=/Written$/ | TargetFileName=/(artex-\d+\.\d+\.\d+-(linux|darwin|windows)-(amd64|arm64)\.zip|_ca[\\\/]mitmproxy-ca-cert\.pem)$/i
// | table([@timestamp, ComputerName, TargetFileName, ContextBaseFileName])
```

```
// 3. AI coding-assistant histories and AI provider keys read by generic tools (not the assistant itself)
#event_simpleName=ProcessRollup2
| CommandLine=/([\\\/]\.claude([\\\/]|\.json)|[\\\/]\.codex[\\\/]|[\\\/]\.gemini[\\\/]|[\\\/]\.cursor[\\\/]|[\\\/]\.aider|[\\\/]\.continue[\\\/]|github-copilot|[\\\/]\.anthropic|ANTHROPIC_API_KEY|OPENAI_API_KEY|DEEPSEEK_API_KEY|sk-ant-|\/proc\/(\d+|\*)\/environ)/i
| FileName=/^(cat|tar|zip|7z|grep|rg|find|base64|curl|wget|scp|rsync|python3?|powershell\.exe|pwsh|cmd\.exe|bash|sh|strings|xxd)$/i
| ParentBaseFileName!=/^(claude|codex|gemini|cursor|code|node)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
```

## Notes

ARTEX ships its console exposed to the internet by default, often with default credentials (Wiz), so also check your external attack surface for anything answering on 8787 with ARTEX's title or favicon (Shodan favicon hash `-576220750`, per pentestit). A hit in query 1 needs a quick answer to "who approved this?": if nobody did, treat the host as an attacker operator box and everything it could reach as exposed. Query 2 will catch legitimate AI-assisted security teams too; that is the point, because Wiz notes that the same tools are used on both sides. For query 3, the riskiest finding is a coding-assistant history copied off a developer laptop or build server, since Wiz's operator mined those histories for production SSO credentials: rotate any credential that was ever pasted into an assistant session on that host. The `llmApis` list is a starting set; add your own approved and blocked providers.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
