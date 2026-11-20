# CyberDetect

Threat hunting queries for **Microsoft Defender XDR / Sentinel (KQL)** and **CrowdStrike Falcon (CQL / LogScale)**, written alongside a daily threat-intelligence briefing focused on the **energy and mining** sectors.

Each hunt is one Markdown file with the query name, what it hunts for, the threat or CVE behind it, the MITRE ATT&CK mapping, and copy-ready queries for each platform. **Newest briefing first.**

## Hunt index (newest first)

### Friday, Nov 20, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-028](hunts/CD-028-cve-exposure-2026-11-20.md) | CVE Exposure Check: Nov 20 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-027](hunts/CD-027-ncentral-cryptominer-4everable2shell.md) | Crypto Miners on RMM Servers (N-central 4EverAble2Shell) | Impact | Defender + CrowdStrike |
| [CD-026](hunts/CD-026-checkpoint-php2shell-tsga-esxi-wiper.md) | Check Point Gateway to ESXi Wiper (PHP2Shell, TSGA, destroy_v6) | Initial Access / Impact | Defender + Sentinel + CrowdStrike |
| [CD-025](hunts/CD-025-vcenter-vmdir-auth-bypass-armory-castle.md) | vCenter Directory Service Abuse (CVE-2026-123890, ARMORY CASTLE) | Initial Access / Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-008](hunts/CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

### Thursday, Nov 19, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-024](hunts/CD-024-cve-exposure-2026-11-19-java4shell.md) | CVE Exposure Check: Nov 19 Briefing (incl. Java4Shell) | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-021](hunts/CD-021-as-rep-roasting.md) | AS-REP Roasting After Server Compromise | Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-020](hunts/CD-020-identity-device-code-legacy-auth-mfa-registration.md) | Identity: Device-Code and Legacy-Auth Sign-ins, New MFA/Passkey Registrations | Cloud Identity | Sentinel |
| [CD-019](hunts/CD-019-rogue-screenconnect-service.md) | Rogue ScreenConnect Client Installed as a Service | Persistence | Defender + CrowdStrike |
| [CD-018](hunts/CD-018-agent-framework-pypi-stealer.md) | Malicious agent-framework PyPI Package (1.26.1 / 1.26.2) | Supply Chain | Defender + CrowdStrike |
| [CD-017](hunts/CD-017-network-iocs-confluence-ncentral-optimizely.md) | Network Indicators: Confluence/Axis, N-central, Optimizely, SCKit Wave 2 | Command and Control | Defender + CrowdStrike |
| [CD-016](hunts/CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells | Initial Access / Exploitation | Defender + CrowdStrike |

### Thursday, Nov 12, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-023](hunts/CD-023-cve-exposure-2026-11-12.md) | CVE Exposure Check: Nov 12 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-015](hunts/CD-015-aws-third-party-role-assumption-qubole.md) | AWS: Third-Party Role Assumption (Qubole Supply Chain) | Cloud / Supply Chain | Sentinel |
| [CD-014](hunts/CD-014-web-server-spawning-shells.md) | Web Server Processes Spawning Shells | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-013](hunts/CD-013-sckit-network-iocs-screenconnect-baseline.md) | SCKit Network Indicators and Unknown ScreenConnect Instances | Command and Control | Defender + CrowdStrike |
| [CD-012](hunts/CD-012-sckit-host-artifacts.md) | SCKit Host Artifacts (Files, Processes, Scheduled Task, Run Key) | Persistence | Defender + CrowdStrike |

### Wednesday, Nov 11, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-022](hunts/CD-022-cve-exposure-2026-11-11.md) | CVE Exposure Check: Nov 11 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-011](hunts/CD-011-siemens-software-center-dll-sideload.md) | Siemens Software Center DLL Side-Loading | Execution / Defense Evasion | Defender + CrowdStrike |
| [CD-010](hunts/CD-010-clickfix-run-dialog-finger.md) | ClickFix: Commands From the Run Dialog and finger.exe Abuse | Execution | Defender + CrowdStrike |
| [CD-009](hunts/CD-009-cpguard-supply-chain-script-execution.md) | cPGuard Processes Downloading or Running Scripts | Supply Chain | Defender + CrowdStrike |
| [CD-008](hunts/CD-008-ransomware-precursors.md) | Ransomware Precursors (Shadow Copy Deletion, Log Clearing, Recovery Disable) *(reused 11-12, 11-19, 11-20)* | Impact | Defender + CrowdStrike |
| [CD-007](hunts/CD-007-ot-industrial-protocols-to-public-ip.md) | OT: Industrial Protocols Going to Public IPs | OT / ICS | Defender + CrowdStrike |
| [CD-006](hunts/CD-006-sshd-spawning-shells.md) | SSH Sessions Spawning Shells (Rare Accounts) *(reused 11-12)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-005](hunts/CD-005-sap-processes-spawning-shells.md) | SAP Kernel Processes Spawning Shells *(reused 11-12)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-004](hunts/CD-004-service-principal-signin-new-ip.md) | Service Principals Signing In From New IPs | Cloud Identity | Defender |
| [CD-003](hunts/CD-003-new-local-accounts-group-additions.md) | New Local Accounts or Local Group Additions (RMM Takeover) *(reused 11-12)* | Persistence | Defender + CrowdStrike |
| [CD-002](hunts/CD-002-dc-lsass-unexpected-children.md) | Domain Controller: Unexpected Child Processes of lsass.exe | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-001](hunts/CD-001-outlook-external-smb-ntlm-leak.md) | Outlook Connecting to External SMB (NTLM Hash Leak) | Credential Access | Defender + CrowdStrike |

## CVE index (newest first)

### 2026-11-20

| CVE | Product / issue | Hunts |
|---|---|---|
| CVE-2026-123890 | VMware vCenter vmdir auth bypass (exploited as zero-day per Google; not in KEV as of Nov 20) | CD-025, CD-028 |
| CVE-2026-123891, CVE-2026-123892, CVE-2026-123893 | VMware SDDC Manager SQLi / command injection / root escalation | CD-028 |
| CVE-2026-123894 | VMware Tools for Windows SAML bypass | CD-028 |
| CVE-2026-102764 | BeyondTrust Remote Support (KEV; initial access in vCenter intrusion) | CD-025, CD-028 |
| CVE-2026-109618, CVE-2026-109619 | PHP2Shell (KEV; Check Point gateway intrusions) | CD-026, CD-028 |
| CVE-2026-123039 | Check Point Gaia DynamicCLI root escalation (KEV) | CD-026, CD-028 |
| CVE-2026-115560 | PHP session serializer RCE (fixed Nov 19) | CD-028 |
| CVE-2026-129271, CVE-2026-129272, CVE-2026-129286 | N-central HF3 (public PoC) | CD-027, CD-028 |

### 2026-11-19

| CVE | Product / issue | Hunts |
|---|---|---|
| CVE-2026-90436 | Apache Axis 1.x in Confluence DC and N-central (exploited, KEV) | CD-016, CD-017, CD-024 |
| CVE-2026-115731 | Puppet Enterprise / OpenVox RCE (exploited, KEV) | CD-016, CD-024 |
| CVE-2026-115732 | Puppet node impersonation | CD-024 |
| CVE-2026-129448 | Apache Roller XML-RPC deserialization (exploited) | CD-016, CD-024 |
| CVE-2026-114938 | Java4Shell: Java Base64 decoder RCE | CD-016, CD-024 |
| CVE-2024-10441 | Synology DSM (KEV) | CD-024 |
| CVE-2026-90817 | REDCap (KEV) | CD-024 |
| CVE-2026-40217 | LiteLLM sandbox escape (KEV) | CD-024 |
| CVE-2026-123007 | NGINX nginx2root HTTP/2 | CD-014, CD-024 |
| CVE-2026-115560 | PHP critical (expected ID) | CD-014, CD-024 |
| CVE-2026-84869 | ScreenConnect client (exploited) | CD-017, CD-019, CD-024 |
| CVE-2026-123039 | Check Point (KEV Nov 13) | CD-024 |
| CVE-2026-114713 | UnrealIRCd (KEV Nov 13) | CD-024 |

### 2026-11-12

| CVE | Product / issue | Hunts |
|---|---|---|
| CVE-2026-119618 | Apache HTTP Server mod_http2 RCE | CD-014, CD-023 |
| CVE-2026-121529 | FortiClient Fortinet2Shell | CD-023 |
| CVE-2026-126261 | FortiManager FGFM RCE | CD-023 |
| CVE-2026-126253 | FortiOS OSPF auth bypass | CD-023 |
| CVE-2026-126147 | FortiMail unauthenticated RCE | CD-023 |
| CVE-2026-121653 | Ivanti Endpoint Manager SQLi | CD-023 |
| CVE-2026-121683 | Ivanti Cloud Services Application | CD-023 |
| CVE-2026-102895 | GPUStack (KEV) | CD-023 |
| VSA-2026-062/063 | Xen Orchestra auth bypass / XCP-ng zero-day (no CVE) | CD-023 |

### 2026-11-11

| CVE | Product / issue | Hunts |
|---|---|---|
| CVE-2026-124194 | Outlook NTLMv2 hash leak (exploited, KEV) | CD-001, CD-022 |
| CVE-2026-125350 | Chrome XML use-after-free (exploited, KEV) | CD-022 |
| CVE-2026-119958 | Windows LDAP RCE | CD-002, CD-022 |
| CVE-2026-118207 | Exchange Server RCE | CD-022 |
| CVE-2026-112967 | Xbox Live Networking RCE | CD-022 |
| CVE-2026-76964, CVE-2026-89126 | SAP ICM2SHELL | CD-005, CD-022 |
| CVE-2026-89103 | SAP PROXYGATE | CD-005, CD-022 |
| CVE-2026-120017 | SAP SAML2 bypass | CD-005, CD-022 |
| CVE-2026-123158 | OpenSSH SSHole (KEV) | CD-006, CD-022 |
| CVE-2026-111497 | Node2Shell / Brotli (KEV) | CD-022 |
| CVE-2026-110936 | Siemens Software Center side-loading (KEV) | CD-011, CD-022 |
| CVE-2026-116606, CVE-2026-111560 | Barracuda ESG chain (exploited, KEV) | CD-003, CD-022 |
| CVE-2026-20320 | Cisco BroadWorks XXE (KEV) | CD-022 |
| CVE-2026-111793 | Openwave Webtop (KEV) | CD-022 |
| CVE-2026-19868 | SonicWall SSLVPN (KEV) | CD-022, CD-024 |
| CVE-2026-123218, CVE-2026-116779 | IBM Aspera Faspex, FreeSWITCH (KEV) | CD-022 |

## Sigma rules

| Rule | Description |
|---|---|
| [outlook-outbound-smb-external.yml](sigma/outlook-outbound-smb-external.yml) | Outlook SMB to a public address (CVE-2026-124194). Same logic as CD-001. |
| [sap-server-process-spawning-shell.yml](sigma/sap-server-process-spawning-shell.yml) | SAP kernel processes spawning shells. Same logic as CD-005. |

## Suggested run order

1. The newest **CVE exposure check** (CD-028, then CD-024, CD-023, CD-022), to see which hosts are affected at all.
2. Hunts for confirmed-exploited threats: CD-025, CD-026, CD-027, CD-016, CD-017, CD-019, CD-021, CD-012, CD-013, CD-003, CD-001.
3. Supply-chain checks: CD-018, CD-015, CD-009.
4. Standing hunts: CD-008 (ransomware precursors), CD-007 (OT exposure), CD-020 and CD-004 (identity).

## Repository layout

```
CyberDetect/
├── README.md
├── hunts/      one file per hunt (CD-001 … CD-028), with its own newest-first README index
└── sigma/      vendor-agnostic Sigma rules
```

New hunts get the next CD number and are listed at the top of the index (here and in [hunts/README.md](hunts/README.md)) under their briefing date. A query reused on a later day keeps its original ID.

## Before you run a query

- **Defender:** table names follow the Defender XDR advanced hunting schema. `EntraIdSpnSignInEvents` needs Entra ID P2. Queries labelled *Sentinel* need the matching data connector (Entra ID, AWS CloudTrail, Windows Security Events).
- **CrowdStrike:** event names were checked against the Falcon Events Data Dictionary; some field names are unverified. Confirm fields in your Falcon console. Network events carry no host name, so several queries join `aidmaster` for `ComputerName`.
- **IOC sweeps** (CD-013, CD-017, CD-026) go stale quickly. Keep lookbacks short and re-check indicators before blocking.
- Appliances (Barracuda, SonicWall, Fortinet, Synology, SAP gateways, Check Point, vCenter, ESXi) often run no EDR agent; check their own logs.
- Every query is a hunting starting point, not a tuned production detection. Baseline, tune and test before use.

## Disclaimer

Provided as-is for defensive security use. Indicators and CVE details come from open-source reporting at the time of writing and may change.
