# Hunts

One file per hunt. **Newest briefing first.** GitHub lists the files above by name (CD-001 first); use this index to see the newest hunts at the top. Each hunt has the query name, what it hunts for, the threat or CVE, MITRE ATT&CK mapping, and Defender (KQL) / CrowdStrike (CQL) queries.

Full CVE index and run order: [main README](../README.md).

## Hunt index (newest first)


### Monday, Nov 23, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-041](CD-041-cve-exposure-2026-11-23.md) | CVE Exposure Check: Nov 23 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-040](CD-040-autonomous-ai-pentest-framework-intrusion-cairn-iocs-spray.md) | Autonomous AI Pentest-Framework Intrusions (Cairn / CL-STA-1238 / Operation Snowball): IOCs, Spraying, Fast Admin Creation | Initial Access / Credential Access | Sentinel + Defender + CrowdStrike |
| [CD-039](CD-039-iis-w3wp-idunno-anticsrf-deserialization-cve-2026-131914.md) | IIS Worker Process Exploitation via Idunno.AntiCsrf Deserialization (CVE-2026-131914) | Initial Access / Exploitation | Defender + Sentinel + CrowdStrike |
| [CD-033](CD-033-ghostscript-imagemagick-cups-spawning-shells-upload2shell.md) | Ghostscript / ImageMagick / CUPS Spawning Shells *(reused: Upload2Shell)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-029](CD-029-cisco-expressway-cve-2026-76466-lateral-movement.md) | Cisco Expressway Cluster Takeover *(reused; KEV due today)* | Initial Access / Lateral Movement | Sentinel + Defender + CrowdStrike |
| [CD-025](CD-025-vcenter-vmdir-auth-bypass-armory-castle.md) | vCenter Directory Service Abuse *(reused; KEV due today)* | Initial Access / Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-016](CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells *(reused: SAP NetWeaver EP, Roller; KEV due today)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-014](CD-014-web-server-spawning-shells.md) | Web Server Processes Spawning Shells *(reused: IIS / AntiCsrf)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-008](CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

### Sunday, Nov 22, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-038](CD-038-cve-exposure-2026-11-22.md) | CVE Exposure Check: Nov 22 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-037](CD-037-tomcat-tribes-cluster-unknown-node-cve-2026-133325.md) | Apache Tomcat Cluster (Tribes) Connections From Unknown Nodes (CVE-2026-133325) | Initial Access / Credential Access | Defender + CrowdStrike |
| [CD-036](CD-036-entra-connect-health-tenant-contact-admin-changes.md) | Entra Tenant Contact, Connect Health and Admin Changes (Connect Health API Exposure) | Cloud Identity | Sentinel + Defender + CrowdStrike NG-SIEM |
| [CD-035](CD-035-email-bombing-teams-fake-it-support-remote-access.md) | Email Bombing Followed by External Teams "IT Support" and Remote-Access Tools | Initial Access / Social Engineering | Defender + CrowdStrike |
| [CD-034](CD-034-softether-vpn-bridge-webworm-ntmonitor.md) | Rogue SoftEther VPN Bridge (Webworm "NtMonitor VPN") | Command and Control / Persistence | Defender + CrowdStrike |
| [CD-033](CD-033-ghostscript-imagemagick-cups-spawning-shells-upload2shell.md) | Ghostscript / ImageMagick / CUPS Spawning Shells (Upload2Shell, CVE-2026-125396) | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-031](CD-031-ruby-rails-gitlab-spawning-shells-ruby2shell.md) | Ruby / Rails / GitLab Processes Spawning Shells *(reused: GitLab CVE-2026-110264 EPSS spike)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-029](CD-029-cisco-expressway-cve-2026-76466-lateral-movement.md) | Cisco Expressway Cluster Takeover *(reused; KEV due Nov 23)* | Initial Access / Lateral Movement | Sentinel + Defender + CrowdStrike |
| [CD-025](CD-025-vcenter-vmdir-auth-bypass-armory-castle.md) | vCenter Directory Service Abuse *(reused; KEV due Nov 23)* | Initial Access / Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-016](CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells *(reused: Tomcat, Roller, SAP NetWeaver Java)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-008](CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

### Saturday, Nov 21, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-032](CD-032-cve-exposure-2026-11-21.md) | CVE Exposure Check: Nov 21 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-031](CD-031-ruby-rails-gitlab-spawning-shells-ruby2shell.md) | Ruby / Rails / GitLab Processes Spawning Shells (Ruby2Shell) | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-030](CD-030-python-startup-persistence-monai-label-ai-agent.md) | Python Startup-File Persistence and Reverse Shells (MONAI Label, Cairn AI agents) | Persistence / Execution | Defender + CrowdStrike |
| [CD-029](CD-029-cisco-expressway-cve-2026-76466-lateral-movement.md) | Cisco Expressway Cluster Takeover and Lateral Movement (CVE-2026-76466) | Initial Access / Lateral Movement | Sentinel + Defender + CrowdStrike |
| [CD-025](CD-025-vcenter-vmdir-auth-bypass-armory-castle.md) | vCenter Directory Service Abuse *(reused; now in KEV)* | Initial Access / Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-016](CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells *(reused: Apache Roller, SAP NetWeaver Java)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-008](CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

### Friday, Nov 20, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-028](CD-028-cve-exposure-2026-11-20.md) | CVE Exposure Check: Nov 20 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-027](CD-027-ncentral-cryptominer-4everable2shell.md) | Crypto Miners on RMM Servers (N-central 4EverAble2Shell) | Impact | Defender + CrowdStrike |
| [CD-026](CD-026-checkpoint-php2shell-tsga-esxi-wiper.md) | Check Point Gateway to ESXi Wiper (PHP2Shell, TSGA, destroy_v6) | Initial Access / Impact | Defender + Sentinel + CrowdStrike |
| [CD-025](CD-025-vcenter-vmdir-auth-bypass-armory-castle.md) | vCenter Directory Service Abuse (CVE-2026-123890, ARMORY CASTLE) | Initial Access / Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-008](CD-008-ransomware-precursors.md) | Ransomware Precursors *(reused)* | Impact | Defender + CrowdStrike |

### Thursday, Nov 19, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-024](CD-024-cve-exposure-2026-11-19-java4shell.md) | CVE Exposure Check: Nov 19 Briefing (incl. Java4Shell) | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-021](CD-021-as-rep-roasting.md) | AS-REP Roasting After Server Compromise | Credential Access | Defender + Sentinel + CrowdStrike |
| [CD-020](CD-020-identity-device-code-legacy-auth-mfa-registration.md) | Identity: Device-Code and Legacy-Auth Sign-ins, New MFA/Passkey Registrations | Cloud Identity | Sentinel |
| [CD-019](CD-019-rogue-screenconnect-service.md) | Rogue ScreenConnect Client Installed as a Service | Persistence | Defender + CrowdStrike |
| [CD-018](CD-018-agent-framework-pypi-stealer.md) | Malicious agent-framework PyPI Package (1.26.1 / 1.26.2) | Supply Chain | Defender + CrowdStrike |
| [CD-017](CD-017-network-iocs-confluence-ncentral-optimizely.md) | Network Indicators: Confluence/Axis, N-central, Optimizely, SCKit Wave 2 | Command and Control | Defender + CrowdStrike |
| [CD-016](CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells | Initial Access / Exploitation | Defender + CrowdStrike |

### Thursday, Nov 12, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-023](CD-023-cve-exposure-2026-11-12.md) | CVE Exposure Check: Nov 12 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-015](CD-015-aws-third-party-role-assumption-qubole.md) | AWS: Third-Party Role Assumption (Qubole Supply Chain) | Cloud / Supply Chain | Sentinel |
| [CD-014](CD-014-web-server-spawning-shells.md) | Web Server Processes Spawning Shells | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-013](CD-013-sckit-network-iocs-screenconnect-baseline.md) | SCKit Network Indicators and Unknown ScreenConnect Instances | Command and Control | Defender + CrowdStrike |
| [CD-012](CD-012-sckit-host-artifacts.md) | SCKit Host Artifacts (Files, Processes, Scheduled Task, Run Key) | Persistence | Defender + CrowdStrike |

### Wednesday, Nov 11, 2026

| ID | Hunt | Category | Platforms |
|---|---|---|---|
| [CD-022](CD-022-cve-exposure-2026-11-11.md) | CVE Exposure Check: Nov 11 Briefing | Exposure / Vulnerability | Defender + CrowdStrike |
| [CD-011](CD-011-siemens-software-center-dll-sideload.md) | Siemens Software Center DLL Side-Loading | Execution / Defense Evasion | Defender + CrowdStrike |
| [CD-010](CD-010-clickfix-run-dialog-finger.md) | ClickFix: Commands From the Run Dialog and finger.exe Abuse | Execution | Defender + CrowdStrike |
| [CD-009](CD-009-cpguard-supply-chain-script-execution.md) | cPGuard Processes Downloading or Running Scripts | Supply Chain | Defender + CrowdStrike |
| [CD-008](CD-008-ransomware-precursors.md) | Ransomware Precursors (Shadow Copy Deletion, Log Clearing, Recovery Disable) *(reused 11-12, 11-19, 11-20, 11-21)* | Impact | Defender + CrowdStrike |
| [CD-007](CD-007-ot-industrial-protocols-to-public-ip.md) | OT: Industrial Protocols Going to Public IPs | OT / ICS | Defender + CrowdStrike |
| [CD-006](CD-006-sshd-spawning-shells.md) | SSH Sessions Spawning Shells (Rare Accounts) *(reused 11-12)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-005](CD-005-sap-processes-spawning-shells.md) | SAP Kernel Processes Spawning Shells *(reused 11-12)* | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-004](CD-004-service-principal-signin-new-ip.md) | Service Principals Signing In From New IPs | Cloud Identity | Defender |
| [CD-003](CD-003-new-local-accounts-group-additions.md) | New Local Accounts or Local Group Additions (RMM Takeover) *(reused 11-12)* | Persistence | Defender + CrowdStrike |
| [CD-002](CD-002-dc-lsass-unexpected-children.md) | Domain Controller: Unexpected Child Processes of lsass.exe | Initial Access / Exploitation | Defender + CrowdStrike |
| [CD-001](CD-001-outlook-external-smb-ntlm-leak.md) | Outlook Connecting to External SMB (NTLM Hash Leak) | Credential Access | Defender + CrowdStrike |
