# CyberDetect

Threat hunting queries for **Microsoft Defender XDR / Sentinel (KQL)** and **CrowdStrike Falcon (CQL / LogScale)**, written alongside a daily threat-intelligence briefing focused on the **energy and mining** sectors.

Each hunt is one Markdown file with the query name, what it hunts for, the threat or CVE behind it, the MITRE ATT&CK mapping, and copy-ready queries for each platform.

## Hunt index

| ID | Hunt | Category | Platforms | First published |
|---|---|---|---|---|
| [CD-001](hunts/CD-001-outlook-external-smb-ntlm-leak.md) | Outlook Connecting to External SMB (NTLM Hash Leak) | Credential Access | Defender + CrowdStrike | 2026-11-11 |
| [CD-002](hunts/CD-002-dc-lsass-unexpected-children.md) | Domain Controller: Unexpected Child Processes of lsass.exe | Initial Access / Exploitation | Defender + CrowdStrike | 2026-11-11 |
| [CD-003](hunts/CD-003-new-local-accounts-group-additions.md) | New Local Accounts or Local Group Additions (RMM Takeover) | Persistence | Defender + CrowdStrike | 2026-11-11 |
| [CD-004](hunts/CD-004-service-principal-signin-new-ip.md) | Service Principals Signing In From New IPs | Cloud Identity | Defender | 2026-11-11 |
| [CD-005](hunts/CD-005-sap-processes-spawning-shells.md) | SAP Kernel Processes Spawning Shells | Initial Access / Exploitation | Defender + CrowdStrike | 2026-11-11 |
| [CD-006](hunts/CD-006-sshd-spawning-shells.md) | SSH Sessions Spawning Shells (Rare Accounts) | Initial Access / Exploitation | Defender + CrowdStrike | 2026-11-11 |
| [CD-007](hunts/CD-007-ot-industrial-protocols-to-public-ip.md) | OT: Industrial Protocols Going to Public IPs | OT / ICS | Defender + CrowdStrike | 2026-11-11 |
| [CD-008](hunts/CD-008-ransomware-precursors.md) | Ransomware Precursors (Shadow Copy Deletion, Log Clearing, Recovery Disable) | Impact | Defender + CrowdStrike | 2026-11-11 |
| [CD-009](hunts/CD-009-cpguard-supply-chain-script-execution.md) | cPGuard Processes Downloading or Running Scripts | Supply Chain | Defender + CrowdStrike | 2026-11-11 |
| [CD-010](hunts/CD-010-clickfix-run-dialog-finger.md) | ClickFix: Commands From the Run Dialog and finger.exe Abuse | Execution | Defender + CrowdStrike | 2026-11-11 |
| [CD-011](hunts/CD-011-siemens-software-center-dll-sideload.md) | Siemens Software Center DLL Side-Loading | Execution / Defense Evasion | Defender + CrowdStrike | 2026-11-11 |
| [CD-012](hunts/CD-012-sckit-host-artifacts.md) | SCKit Host Artifacts (Files, Processes, Scheduled Task, Run Key) | Persistence | Defender + CrowdStrike | 2026-11-12 |
| [CD-013](hunts/CD-013-sckit-network-iocs-screenconnect-baseline.md) | SCKit Network Indicators and Unknown ScreenConnect Instances | Command and Control | Defender + CrowdStrike | 2026-11-12 |
| [CD-014](hunts/CD-014-web-server-spawning-shells.md) | Web Server Processes Spawning Shells | Initial Access / Exploitation | Defender + CrowdStrike | 2026-11-12 |
| [CD-015](hunts/CD-015-aws-third-party-role-assumption-qubole.md) | AWS: Third-Party Role Assumption (Qubole Supply Chain) | Cloud / Supply Chain | Sentinel | 2026-11-12 |
| [CD-016](hunts/CD-016-java-app-servers-spawning-shells.md) | Java Application Servers Spawning Shells | Initial Access / Exploitation | Defender + CrowdStrike | 2026-11-19 |
| [CD-017](hunts/CD-017-network-iocs-confluence-ncentral-optimizely.md) | Network Indicators: Confluence/Axis, N-central, Optimizely, SCKit Wave 2 | Command and Control | Defender + CrowdStrike | 2026-11-19 |
| [CD-018](hunts/CD-018-agent-framework-pypi-stealer.md) | Malicious agent-framework PyPI Package (1.26.1 / 1.26.2) | Supply Chain | Defender + CrowdStrike | 2026-11-19 |
| [CD-019](hunts/CD-019-rogue-screenconnect-service.md) | Rogue ScreenConnect Client Installed as a Service | Persistence | Defender + CrowdStrike | 2026-11-19 |
| [CD-020](hunts/CD-020-identity-device-code-legacy-auth-mfa-registration.md) | Identity: Device-Code and Legacy-Auth Sign-ins, New MFA/Passkey Registrations | Cloud Identity | Sentinel | 2026-11-19 |
| [CD-021](hunts/CD-021-as-rep-roasting.md) | AS-REP Roasting After Server Compromise | Credential Access | Defender + Sentinel + CrowdStrike | 2026-11-19 |
| [CD-022](hunts/CD-022-cve-exposure-check.md) | Exposure Check: CVEs and Products From the Briefings | Exposure / Vulnerability | Defender + CrowdStrike | 2026-11-11 |

## Sigma rules

| Rule | Description |
|---|---|
| [outlook-outbound-smb-external.yml](sigma/outlook-outbound-smb-external.yml) | Outlook SMB to a public address (CVE-2026-124194). Same logic as CD-001. |
| [sap-server-process-spawning-shell.yml](sigma/sap-server-process-spawning-shell.yml) | SAP kernel processes spawning shells. Same logic as CD-005. |

## Suggested run order

1. **CD-022** exposure check, to see which hosts are affected at all.
2. Hunts for confirmed-exploited threats: CD-016, CD-017, CD-003, CD-012, CD-013, CD-019, CD-001.
3. Supply-chain checks: CD-018, CD-009, CD-015.
4. Standing hunts: CD-008 (ransomware precursors), CD-007 (OT exposure), CD-020 (identity).

## Repository layout

```
CyberDetect/
├── README.md
├── hunts/      one file per hunt (CD-001 … CD-022)
└── sigma/      vendor-agnostic Sigma rules
```

## Before you run a query

- **Defender:** table names follow the Defender XDR advanced hunting schema. `EntraIdSpnSignInEvents` needs Entra ID P2. Queries labelled *Sentinel* need the matching data connector (Entra ID, AWS CloudTrail, Windows Security Events).
- **CrowdStrike:** event names were checked against the Falcon Events Data Dictionary; some field names are unverified. Confirm fields in your Falcon console. Network events carry no host name, so several queries join `aidmaster` for `ComputerName`.
- **IOC sweeps** (CD-013, CD-017) go stale quickly. Keep lookbacks short and re-check indicators before blocking.
- Appliances (Barracuda, SonicWall, Fortinet, Synology, SAP gateways) often run no EDR agent; check their own logs.
- Every query is a hunting starting point, not a tuned production detection. Baseline, tune and test before use.

## Disclaimer

Provided as-is for defensive security use. Indicators and CVE details come from open-source reporting at the time of writing and may change.
