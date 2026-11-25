# CD-048 · Agentic Kubernetes Node Escape and Persistence (privileged root-mount pods, nsenter, kubelet PKI theft, IMDS kube-env, `ld.so.preload` rootkit disguised as fontconfig)
| | |
|---|---|
| **Hunts for** | (1) On Linux nodes: writes to `/etc/ld.so.preload`, `nsenter` into PID 1 namespaces, reads of the kubelet PKI, kubeconfig and projected service-account tokens by anything that is not the kubelet, IMDS `kube-env` / credential queries from inside pods, and new systemd units or binaries posing as fontconfig; (2) in Kubernetes audit logs (AKS): privileged or `hostPID` pods mounting the node root filesystem, pods named `csai-*` / `pentest-*` / "collector", new `cluster-admin` bindings, and token requests for many service accounts; (3) DNS-tunnel style queries from nodes (the rootkit's C2 channel). |
| **Threat / CVE** | Wiz **ARTEX-Harvester**: stolen app-pod service-account token → privileged pods with the node root filesystem mounted → a "node-level collector" pod harvested kubelet PKI and projected tokens → a cert-manager token read ArgoCD secrets → cluster-admin. Wiz **"Both Sides" (CyberStrikeAI)**: stolen Terraform-runner session read the kubelet kubeconfig, created a privileged pod (`csai-escape`) and a cluster-admin binding, then a pod escape installed an `ld.so.preload` userland rootkit with a DNS-tunnel channel, disguised as a fontconfig service, with **zero VirusTotal detections**. No CVE (credential and misconfiguration abuse). |
| **MITRE ATT&CK** | T1611 Escape to Host, T1610 Deploy Container, T1574.006 Dynamic Linker Hijacking, T1014 Rootkit, T1552.005 Cloud Instance Metadata API, T1528 Steal Application Access Token, T1543.002 Systemd Service, T1572 Protocol Tunneling, T1098 Account Manipulation |
| **Category** | Privilege Escalation / Persistence (containers) |
| **First published** | 2026-11-25 (ARTEX special, from the Wiz report) |

## Microsoft Defender XDR / Sentinel (KQL)

```kql
// 1. Linux node escape and rootkit artifacts (Defender for Endpoint on Linux / Defender for Containers sensor)
let lookback = 30d;
union isfuzzy=true
 (DeviceFileEvents | where Timestamp > ago(lookback)
    | where FolderPath == "/etc/ld.so.preload" or (FolderPath startswith "/etc/" and FileName == "ld.so.preload")
    | project Timestamp, DeviceName, Signal="ld.so.preload written", Detail=strcat(ActionType, " by ", InitiatingProcessFileName, " ", InitiatingProcessCommandLine)),
 (DeviceProcessEvents | where Timestamp > ago(lookback)
    | where FileName == "nsenter" and ProcessCommandLine matches regex @"(-t\s*1\b|--target[= ]1\b)"
    | project Timestamp, DeviceName, Signal="nsenter into PID 1", Detail=strcat(InitiatingProcessFileName, " > ", ProcessCommandLine)),
 (DeviceProcessEvents | where Timestamp > ago(lookback)
    | where ProcessCommandLine has_any ("ld.so.preload", "/var/lib/kubelet/pki", "/var/lib/kubelet/kubeconfig", "/etc/kubernetes/kubelet.conf", "/var/run/secrets/kubernetes.io/serviceaccount/token", "/var/lib/kubelet/pods/")
    | where InitiatingProcessFileName !in~ ("kubelet", "containerd", "dockerd", "containerd-shim-runc-v2")
    | project Timestamp, DeviceName, Signal="kubelet PKI / token / preload access", Detail=strcat(InitiatingProcessFileName, " > ", ProcessCommandLine)),
 (DeviceProcessEvents | where Timestamp > ago(lookback)
    | where ProcessCommandLine has "169.254.169.254" or ProcessCommandLine has "metadata.google.internal"
    | where ProcessCommandLine has_any ("kube-env", "iam/security-credentials", "service-accounts/default/token", "instance/attributes")
    | project Timestamp, DeviceName, Signal="IMDS kube-env / credential query", Detail=strcat(InitiatingProcessFileName, " > ", ProcessCommandLine)),
 (DeviceFileEvents | where Timestamp > ago(lookback) | where ActionType == "FileCreated"
    | where (FolderPath startswith "/etc/systemd/system/" or FolderPath startswith "/lib/systemd/system/" or FolderPath startswith "/usr/lib/systemd/system/")
    | where FileName matches regex @"(?i)font"
    | where InitiatingProcessFileName !in~ ("dpkg", "rpm", "dnf", "yum", "apt", "apt-get", "unattended-upgr", "packagekitd")
    | project Timestamp, DeviceName, Signal="fontconfig-named systemd unit (not package manager)", Detail=strcat(FolderPath, " by ", InitiatingProcessFileName))
| order by Timestamp desc
```

```kql
// 2. AKS audit (Sentinel AKSAudit / resource-specific kube-audit): root-mount privileged pods, agent-named pods,
//    cluster-admin bindings and mass service-account token creation
AKSAudit
| where TimeGenerated > ago(30d)
| where Verb == "create"
| extend Resource = tostring(ObjectRef.resource), Sub = tostring(ObjectRef.subresource), Name = tostring(ObjectRef.name), NS = tostring(ObjectRef.namespace)
| extend Req = tostring(RequestObject), Who = tostring(User.username)
| extend Signal = case(
    Resource == "pods" and Req has "\"privileged\":true" and Req matches regex @"""hostPath"":\{""path"":""/""", "Privileged pod mounting node root /",
    Resource == "pods" and (Req has "\"hostPID\":true" or Req has "\"hostNetwork\":true") and Req has "\"privileged\":true", "Privileged hostPID/hostNetwork pod",
    Resource == "pods" and Name matches regex @"(?i)^(csai-|pentest-|artex|node-?collector|collector-)", "Agent-named pod",
    Resource in ("clusterrolebindings", "rolebindings") and Req has "cluster-admin", "Binding to cluster-admin",
    Resource == "serviceaccounts" and Sub == "token", "SA token request",
    "")
| where isnotempty(Signal)
| summarize Events=count(), Names=make_set(strcat(NS, "/", Name), 25), SourceIPs=make_set(SourceIps, 10), First=min(TimeGenerated), Last=max(TimeGenerated) by Signal, Who
| where Signal != "SA token request" or array_length(Names) >= 5   // "tokens for multiple service accounts"
| order by First desc
```

```kql
// 3. DNS-tunnel style lookups from Linux nodes: long, high-cardinality subdomains under one parent domain
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsConnectionInspected"
| extend Q = tostring(parse_json(AdditionalFields).query)
| where strlen(Q) > 60
| extend Parent = strcat_array(array_slice(split(Q, "."), -2, -1), ".")
| summarize Lookups=count(), Unique=dcount(Q), MaxLen=max(strlen(Q)), Sample=take_any(Q), Procs=make_set(InitiatingProcessFileName, 10) by DeviceName, Parent
| where Unique > 50
| order by Unique desc
```

## CrowdStrike Falcon (CQL)

```
// 1. Falcon for Linux / containers: ld.so.preload, nsenter into PID 1, kubelet PKI and token reads, IMDS kube-env
#event_simpleName=ProcessRollup2 event_platform=Lin
| case {
    CommandLine=/ld\.so\.preload/ | Signal := "ld.so.preload referenced";
    FileName="nsenter" CommandLine=/(-t\s*1\b|--target[= ]1\b)/ | Signal := "nsenter into PID 1";
    CommandLine=/(\/var\/lib\/kubelet\/pki|\/var\/lib\/kubelet\/kubeconfig|\/etc\/kubernetes\/kubelet\.conf|serviceaccount\/token)/ ParentBaseFileName!=/^(kubelet|containerd.*|dockerd)$/ | Signal := "kubelet PKI / SA token access";
    CommandLine=/(169\.254\.169\.254|metadata\.google\.internal)/ CommandLine=/(kube-env|security-credentials|service-accounts\/default\/token|instance\/attributes)/ | Signal := "IMDS kube-env / credential query";
  }
| table([@timestamp, ComputerName, Signal, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
```

```
// 2. Falcon for Linux: files written to /etc/ld.so.preload or fontconfig-named systemd units (event names vary by sensor; verify)
#event_simpleName=/(Written$|FileOpenInfo|CriticalFileModified|LinuxFileWritten)/ event_platform=Lin
| TargetFileName=/^\/etc\/ld\.so\.preload$/ OR TargetFileName=/^\/(etc|lib|usr\/lib)\/systemd\/system\/.*font.*\.service$/i
| ContextBaseFileName!=/^(dpkg|rpm|dnf|yum|apt|apt-get)$/
| table([@timestamp, ComputerName, #event_simpleName, TargetFileName, ContextBaseFileName, UserName])
```

```
// 3. Falcon DNS: tunnel-like lookups from Linux hosts (long, many unique names per parent domain)
#event_simpleName=DnsRequest event_platform=Lin
| length(DomainName, as=qlen)
| qlen > 60
| regex("(?<Parent>[^.]+\.[^.]+)$", field=DomainName)
| groupBy([aid, Parent], function=[count(as=Lookups), count(DomainName, distinct=true, as=Unique), max(qlen, as=MaxLen)])
| Unique > 50
| join(query={#data_source_name=aidmaster | groupBy([aid], function=selectLast([ComputerName]))}, field=[aid], include=[ComputerName])
| sort(Unique, order=desc)
```

## Notes

Wiz found the rootkit had **zero VirusTotal detections**, so hash and signature checks will not find it; behaviour on the node is the signal. Also check directly: `cat /etc/ld.so.preload` on every node should print nothing on most distributions, and any library listed there that no package owns is a finding. Kubernetes audit logging must be on (AKS diagnostic setting `kube-audit` or `kube-audit-admin`; for EKS send control-plane `audit` logs to CloudWatch and on to Sentinel/NG-SIEM, where the same pod-spec logic applies to the `requestObject` field). If you find a root-mount pod or a new `cluster-admin` binding you did not deploy: cordon the node, rotate the kubelet certificates, every service-account token and the cloud identity (IRSA / workload identity) on that node, and check ArgoCD and cert-manager secrets, as Wiz describes. Field names and event types for Falcon on Linux differ by sensor version and should be confirmed.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
