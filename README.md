# CyberDetect

Threat hunting queries for **Microsoft Defender XDR / Sentinel (KQL)** and **CrowdStrike Falcon (CQL / LogScale)**, written alongside a daily threat-intelligence briefing focused on the **energy and mining** sectors.

Each hunt is one Markdown file with the query name, what it hunts for, the threat or CVE behind it, the MITRE ATT&CK mapping, and copy-ready queries for each platform. **Newest briefing first.**

## Hunt index (newest first)

### Tuesday, Nov 24, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-044](hunts/CD-044-cve-exposure-2026-11-24.md) | CVE Exposure Check: Nov 24 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-043](hunts/CD-043-n-able-mail-assure-ldap-sync-ssrf-cve-2026-134624.md) | N-able Mail Assure / SpamExperts LDAP Sync Abuse (CVE-2026-134624) | Initial Access / Supply Chain | Defender + CrowdStrike |
| [CD-042](hunts/CD-042-azure-apim-classic-secret-exposure-equinor-skagerak.md) | Azure API Management Classic: Secret Reads and Use of Exposed Credentials (Equinor / Skagerak Energi) | Cloud / Credential Access | Sentinel + Defender + CrowdStrike NG-SIEM |
| [CD-030](hunts/CD-030-python-startup-persistence-monai-label-ai-agent.md) | Python Startup-File Persistence and Reverse Shells *(reused: MONAI Label CVE-2026-133968, now KEV)* | Persistence / Execution | Defender + CrowdStrike |
| [CD-040](hunts/CD-040-autonomous-ai-pentest-framework-intrusion-cairn-iocs-spray.md) | Autonomous AI Pentest-Framework Intrusions *(reused: Cairn)* | Initial Access / Credential Access | Sentinel + Defender + CrowdStrike |
| [CD-039](hunts/CD-039-iis-w3wp-idunno-anticsrf-deserialization-cve-2026-131914.md) | IIS Worker Process Exploitation via Idunno.AntiCsrf *(reused; still no patch)* | Initial Access / Exploitation | Defender + Sentinel + CrowdStrike |
| [CD-001](hunts/CD-001-outlook-external-smb-ntlm-leak.md) | Outlook Connecting to External SMB *(reused; KEV due today)* | Credential Access | Defender + CrowdStrike |
| [CD-008](hunts/CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

### Monday, Nov 23, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-041](hunts/CD-041-cve-exposure-2026-11-23.md) | CVE Exposure Check: Nov 23 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-040](hunts/CD-040-autonomous-ai-pentest-framework-intrusion-cairn-iocs-spray.md) | Autonomous AI Pentest-Framework Intrusions (Cairn / CL-STA-1238 / Operation Snowball): IOCs, Spraying, Fast Admin Creation | Initial Access / Credential Access | Sentinel + Defender + CrowdStrike |
| [CD-039](hunts/CD-039-iis-w3wp-idunno-anticsrf-deserialization-cve-2026-131914.md) | IIS Worker Process Exploitation via Idunno.AntiCsrf Deserialization (CVE-2026-131914) | Initial Access / Exploitation | Defender + Sentinel + CrowdStrike |
| [CD-033](hunts/CD-033-ghostscript-imagemagick-cups-spawning-shells-upload2shell.md) | Ghostscript / ImageMagick / CUPS Spawning Shells *(reused: Upload2Shell)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-029](hunts/CD-029-cisco-expressway-cve-2026-76466-lateral-movement.md) | Cisco Expressway Cluster Takeover *(reused; KEV due today)* | Initial Access / Lateral Movement | Sentinel + Defender + CrowdStrike |
| [CD-025](hunts/CD-025-vcenter-vmdir-auth-bypass-armory-castle.md) | vCenter Directory Service Abuse *(reused; KEV due today)* | Initial Access / Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-016](hunts/CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells *(reused: SAP NetWeaver EP, Roller; KEV due today)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-014](hunts/CD-014-web-server-spawning-shells.md) | Web Server Processes Spawning Shells *(reused: IIS / AntiCsrf)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-008](hunts/CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

### Sunday, Nov 22, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-038](hunts/CD-038-cve-exposure-2026-11-22.md) | CVE Exposure Check: Nov 22 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-037](hunts/CD-037-tomcat-tribes-cluster-unknown-node-cve-2026-133325.md) | Apache Tomcat Cluster (Tribes) Connections From Unknown Nodes (CVE-2026-133325) | Initial Access / Credential Access | Defender + CrowdStrike |
| [CD-036](hunts/CD-036-entra-connect-health-tenant-contact-admin-changes.md) | Entra Tenant Contact, Connect Health and Admin Changes (Connect Health API Exposure) | Cloud Identity | Sentinel + Defender + CrowdStrike NG-SIEM |
| [CD-035](hunts/CD-035-email-bombing-teams-fake-it-support-remote-access.md) | Email Bombing Followed by External Teams "IT Support" and Remote-Access Tools | Initial Access / Social Engineering | Defender + CrowdStrike |
| [CD-034](hunts/CD-034-softether-vpn-bridge-webworm-ntmonitor.md) | Rogue SoftEther VPN Bridge (Webworm "NtMonitor VPN") | Command and Control / Persistence | Defender + CrowdStrike |
| [CD-033](hunts/CD-033-ghostscript-imagemagick-cups-spawning-shells-upload2shell.md) | Ghostscript / ImageMagick / CUPS Spawning Shells (Upload2Shell, CVE-2026-125396) | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-031](hunts/CD-031-ruby-rails-gitlab-spawning-shells-ruby2shell.md) | Ruby / Rails / GitLab Processes Spawning Shells *(reused: GitLab CVE-2026-110264 EPSS spike)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-029](hunts/CD-029-cisco-expressway-cve-2026-76466-lateral-movement.md) | Cisco Expressway Cluster Takeover *(reused; KEV due Nov 23)* | Initial Access / Lateral Movement | Sentinel + Defender + CrowdStrike |
| [CD-025](hunts/CD-025-vcenter-vmdir-auth-bypass-armory-castle.md) | vCenter Directory Service Abuse *(reused; KEV due Nov 23)* | Initial Access / Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-016](hunts/CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells *(reused: Tomcat, Roller, SAP NetWeaver Java)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-008](hunts/CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

### Saturday, Nov 21, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-032](hunts/CD-032-cve-exposure-2026-11-21.md) | CVE Exposure Check: Nov 21 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-031](hunts/CD-031-ruby-rails-gitlab-spawning-shells-ruby2shell.md) | Ruby / Rails / GitLab Processes Spawning Shells (Ruby2Shell) | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-030](hunts/CD-030-python-startup-persistence-monai-label-ai-agent.md) | Python Startup-File Persistence and Reverse Shells (MONAI Label, Cairn AI agents) | Persistence / Execution | Defender + CrowdStrike |
| [CD-029](hunts/CD-029-cisco-expressway-cve-2026-76466-lateral-movement.md) | Cisco Expressway Cluster Takeover and Lateral Movement (CVE-2026-76466) | Initial Access / Lateral Movement | Sentinel + Defender + CrowdStrike |
| [CD-025](hunts/CD-025-vcenter-vmdir-auth-bypass-armory-castle.md) | vCenter Directory Service Abuse *(reused; now in KEV)* | Initial Access / Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-016](hunts/CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells *(reused: Apache Roller, SAP NetWeaver Java)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-008](hunts/CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

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
| [CD-008](hunts/CD-008-ransomware-precursors.md) | Ransomware Precursors (Shadow Copy Deletion, Log Clearing, Recovery Disable) *(reused 11-12, 11-19, 11-20, 11-21, 11-22, 11-23)* | Impact | Defender + CrowdStrike |
| [CD-007](hunts/CD-007-ot-industrial-protocols-to-public-ip.md) | OT: Industrial Protocols Going to Public IPs | OT / ICS | Defender + CrowdStrike |
| [CD-006](hunts/CD-006-sshd-spawning-shells.md) | SSH Sessions Spawning Shells (Rare Accounts) *(reused 11-12)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-005](hunts/CD-005-sap-processes-spawning-shells.md) | SAP Kernel Processes Spawning Shells *(reused 11-12)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-004](hunts/CD-004-service-principal-signin-new-ip.md) | Service Principals Signing In From New IPs | Cloud Identity | Defender |
| [CD-003](hunts/CD-003-new-local-accounts-group-additions.md) | New Local Accounts or Local Group Additions (RMM Takeover) *(reused 11-12)* | Persistence | Defender + CrowdStrike |
| [CD-002](hunts/CD-002-dc-lsass-unexpected-children.md) | Domain Controller: Unexpected Child Processes of lsass.exe | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-001](hunts/CD-001-outlook-external-smb-ntlm-leak.md) | Outlook Connecting to External SMB (NTLM Hash Leak) | Credential Access | Defender + CrowdStrike |

## CVE index (newest first)

### 2026-11-24

| CVE | Product / issue | Hunts |
|---|---|---|
| No CVE (MZK9-GH0) | Azure API Management Classic secret exposure; behind Equinor and Skagerak Energi (**exploited**, NSM / Microsoft) | CD-042 |
| CVE-2026-134624 | N-able Mail Assure LDAP sync SSRF (**KEV Nov 23**, due Nov 26) | CD-043, CD-044 |
| CVE-2026-133968 | MONAI Label path traversal RCE, Cairn AI agents (**KEV Nov 23**, due Nov 26) | CD-030, CD-044 |
| CVE-2026-124194, CVE-2026-125350 | Outlook spoofing, Chrome XML use-after-free (KEV, **due today, Nov 24**; Outlook EPSS 0.019 to 0.249) | CD-001, CD-044 |
| CVE-2026-115731 | Puppet Server (KEV, due Dec 1; EPSS 0.012 to 0.128) | CD-016, CD-044 |
| CVE-2021-3199, CVE-2026-45247, CVE-2026-5430, CVE-2024-21410 | ONLYOFFICE, Mirasvit Magento, WSO2 API Manager, Exchange NTLM relay (KEV; EPSS rising) | CD-044 |

### 2026-11-23

| CVE | Product / issue | Hunts |
|---|---|---|
| CVE-2026-131914 | Idunno.AntiCsrf ASP.NET WebForms module, unkeyed ObjectStateFormatter deserialization, unauthenticated RCE (**exploited, Mandiant; no patch**, not in KEV) | CD-039, CD-041 |
| CVE-2026-20320 | Cisco BroadWorks OCI-P XXE (KEV Nov 10; used by jailbroken AI agent in Operation Snowball) | CD-040, CD-041 |
| CVE-2020-7961 | Liferay Portal JSON deserialization (Operation Snowball) | CD-040, CD-041 |
| CVE-2026-123890, CVE-2026-76466, CVE-2025-42884, CVE-2026-129448 | KEV Nov 20, **due today, Nov 23** | CD-025, CD-029, CD-016, CD-041 |
| CVE-2026-124194, CVE-2026-125350 | Outlook spoofing, Chrome XML use-after-free (KEV, due Nov 24; Chrome EPSS 0.0096 to 0.068) | CD-001, CD-041 |
| CVE-2026-123158 | OpenSSH < 10.6p2 on musl without PAM, password auth bypass (KEV; EPSS 0.19 to 0.96) | CD-006, CD-041 |
| CVE-2026-40217 | LiteLLM guardrails custom-code RCE (KEV Nov 18; EPSS 0.17 to 0.78) | CD-041 |
| CVE-2026-116606, CVE-2026-111560 | Barracuda ESG auth bypass and command injection (KEV Nov 10) | CD-041 |
| CVE-2026-50522 | SharePoint deserialization RCE (KEV; EPSS 0.03 to 0.82) | CD-041 |
| CVE-2026-41253 | iTerm2 <= 3.6.9 SSH conductor escape-sequence code execution (public PoC) | CD-041 |
| No CVE | Autonomous AI pentest frameworks (Cairn, CL-STA-1238, AWS medical-imaging zero-day) | CD-040 |

### 2026-11-22

| CVE | Product / issue | Hunts |
|---|---|---|
| CVE-2026-125396 | Upload2Shell: Ghostscript -dSAFER bypass via Type 1 font loader (< 10.08.0; research demos, not in KEV) | CD-033, CD-038 |
| CVE-2026-133325 | Apache Tomcat Tribes cluster join without authentication (TLS 1.3 + PSK; 11.0.28-29, 10.1.62, 9.0.124) | CD-037, CD-038 |
| CVE-2026-101296, CVE-2026-101356, CVE-2026-103119 | Apache Tomcat October fixes (JNDIRealm SASL bypass, HTTP/2 mix-up, response split) | CD-016, CD-038 |
| CVE-2026-110264 | GitLab regex compiler pre-auth RCE (EPSS 0.013 to 0.54 on Nov 21; not in KEV) | CD-031, CD-038 |
| CVE-2026-98432 | Linux kernel IPv4 TCP handshake use-after-free (EPSS 0.008 to 0.82 on Nov 21; not in KEV) | CD-038 |
| CVE-2026-59309 | VMware vCenter vmdir auth bypass, July advisory (EPSS 0.006 to 0.31) | CD-025, CD-038 |
| CVE-2026-123890, CVE-2026-76466, CVE-2025-42884, CVE-2026-129448 | KEV Nov 20, **due Mon Nov 23** | CD-025, CD-029, CD-016, CD-038 |
| CVE-2026-115731 | Puppet Server report deserialization (KEV, due Dec 1) | CD-016, CD-038 |
| No CVE | Entra Connect Health API read exposure of tenant/admin contact data (fixed Nov 19) | CD-036 |
| No CVE | Webworm SoftEther VPN Bridge abuse ("NtMonitor VPN") | CD-034 |

### 2026-11-21

| CVE | Product / issue | Hunts |
|---|---|---|
| CVE-2026-123890 | VMware vCenter vmdir auth bypass (**KEV Nov 20**, due Nov 23) | CD-025, CD-032 |
| CVE-2026-76466 | Cisco Expressway clustered root RCE (KEV Nov 20, due Nov 23; F6 incident) | CD-029, CD-032 |
| CVE-2025-42884 | SAP NetWeaver Enterprise Portal JNDI injection (KEV Nov 20, due Nov 23) | CD-016, CD-032 |
| CVE-2026-129448 | Apache Roller XML-RPC deserialization (KEV Nov 20, due Nov 23) | CD-016, CD-032 |
| CVE-2026-133968 | MONAI Label path traversal, exploited by Cairn AI agents (not in KEV, no patched release) | CD-030, CD-032 |
| CVE-2026-132825 | Ruby2Shell, Ruby String case conversion overflow (public PoC) | CD-031, CD-032 |
| CVE-2026-123637, CVE-2026-121805, CVE-2026-120722, CVE-2026-120292, CVE-2026-120285, CVE-2026-116953 | F5 BIG-IP TMM stack overflows (DoS, possible RCE) | CD-032 |
| CVE-2026-126822 | F5 BIG-IP APM SAML SP TMM crash | CD-032 |
| CVE-2026-129975 | GPGME long user ID memory bug | CD-032 |

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

1. The newest **CVE exposure check** (CD-044, then CD-041, CD-038, CD-032, CD-028, CD-024, CD-023, CD-022), to see which hosts are affected at all.
2. Hunts for confirmed-exploited threats: CD-042, CD-043, CD-039, CD-040, CD-029, CD-034, CD-035, CD-036, CD-025, CD-030, CD-026, CD-027, CD-016, CD-017, CD-019, CD-021, CD-012, CD-013, CD-003, CD-001.
3. Public PoC or research demo, no exploitation reported yet: CD-033 (Upload2Shell), CD-037 (Tomcat cluster), CD-031 (Ruby2Shell, GitLab). Supply-chain checks: CD-018, CD-015, CD-009.
4. Standing hunts: CD-008 (ransomware precursors), CD-007 (OT exposure), CD-020 and CD-004 (identity).

## Repository layout

```
CyberDetect/
├── README.md
├── hunts/      one file per hunt (CD-001 … CD-044), with its own newest-first README index
└── sigma/      vendor-agnostic Sigma rules
```

New hunts get the next CD number and are listed at the top of the index (here and in [hunts/README.md](hunts/README.md)) under their briefing date. A query reused on a later day keeps its original ID.

## Before you run a query

- **Defender:** table names follow the Defender XDR advanced hunting schema. `EntraIdSpnSignInEvents` needs Entra ID P2. Queries labelled *Sentinel* need the matching data connector (Entra ID, AWS CloudTrail, Windows Security Events).
- **CrowdStrike:** event names were checked against the Falcon Events Data Dictionary; some field names are unverified. Confirm fields in your Falcon console. Network events carry no host name, so several queries join `aidmaster` for `ComputerName`.
- **IOC sweeps** (CD-013, CD-017, CD-026, CD-029, CD-034, CD-040) go stale quickly. Keep lookbacks short and re-check indicators before blocking.
- Appliances (Barracuda, SonicWall, Fortinet, Synology, SAP gateways, Check Point, vCenter, ESXi, Cisco Expressway, F5 BIG-IP) often run no EDR agent; check their own logs.
- Every query is a hunting starting point, not a tuned production detection. Baseline, tune and test before use.

## Disclaimer

Provided as-is for defensive security use. Indicators and CVE details come from open-source reporting at the time of writing and may change.
