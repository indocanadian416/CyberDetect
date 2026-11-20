# CD-025 · vCenter Directory Service Abuse (CVE-2026-123890, ARMORY CASTLE)
| | |
|---|---|
| **Hunts for** | Signs that the vCenter authentication bypass was used: connections to the VMware Directory Service RPC port (TCP 2012) from hosts that are not vCenter or admin jump hosts, SSO administrator accounts nobody created, SSH switched on and then off on the vCenter appliance, and the BEARBONES backdoored Dropbear SSH server. |
| **Threat / CVE** | CVE-2026-123890 (VMware vCenter, CVSS 9.8, exploited as a zero-day since early Sept 2026); initial access via BeyondTrust Remote Support CVE-2026-102764 (KEV) |
| **MITRE ATT&CK** | T1190 Exploit Public-Facing Application, T1136.003 Create Cloud Account, T1606.002 Forge Web Credentials: SAML Tokens, T1021.004 SSH, T1505.003 Web Shell |
| **Category** | Initial Access / Credential Access (virtualization) |
| **First published** | 2026-11-20 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// Connections to the vmdir RPC port (2012). Replace mgmt with your vCenter and admin jump-host IPs.
let mgmt = dynamic(["10.0.0.10","10.0.0.11"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort == 2012
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where LocalIP !in (mgmt)
| summarize Connections=count(), Targets=make_set(RemoteIP, 20), First=min(Timestamp), Last=max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Connections desc
```

```kql
// BEARBONES: SSH banner seen by Defender network inspection (needs network protection / SSH inspection)
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "SshConnectionInspected"
| where AdditionalFields has "pulsesecure_23345"
| project Timestamp, DeviceName, LocalIP, RemoteIP, RemotePort, AdditionalFields
```

```kql
// Dropbear SSH servers on Linux appliances that have the Defender agent
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName startswith "dropbear" or ProcessCommandLine has "dropbear"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

## Microsoft Sentinel (vCenter syslog)

```kql
// vCenter SSO admin changes and SSH enable/disable on the appliance.
// Field names depend on how vCenter syslog is forwarded; tune ProcessName and message text to your logs.
Syslog
| where TimeGenerated > ago(90d)
| where Computer has_any ("vcenter","vcsa") or ProcessName in~ ("vmdird","sso","sshd","applmgmt","vami")
| where SyslogMessage has_any ("CreateLocalPersonUser","AddUsersToLocalGroup","PrincipalManagement","Administrators")
    or (SyslogMessage has "ssh" and SyslogMessage has_any ("enable","disable","Enabled","Disabled"))
| project TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=NetworkConnectIP4 RemotePort=2012
| join(query={#data_source_name=aidmaster | groupBy([aid], function=selectLast([ComputerName]))}, field=[aid], include=[ComputerName])
| groupBy([ComputerName, RemoteAddressIP4], function=count())
```

```
#event_simpleName=ProcessRollup2 (FileName=/^dropbear/i OR CommandLine=/dropbear|pulsesecure_23345/i)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

Attack chain reported by Mandiant/GTIG: BeyondTrust Remote Support (CVE-2026-102764) → internal Linux appliance with no EDR → scan for VMware services incl. TCP 2012 → CVE-2026-123890 leaks an SRP session key from vmdir → super-admin session. BONESAW copied the directory database, stole the SAML signing key and created an SSO admin; SAWSNAKE forged SAML tokens. The actor enabled SSH on vCenter, took the master key and PostgreSQL credentials, then disabled SSH, and pulled Active Directory database files from guest VM disks. Persistence: BEARBONES (Dropbear, logs passwords), LAZYBONES (Slack-controlled), SLIMSAVAGE and CAGEMATCH (JSP web shells). No public hashes, IPs or domains were found in the coverage read.

vCenter appliances do not run Defender or Falcon, so the network hunts only see the client side (the host that connects to 2012). Also review vCenter SSO users by hand, the VAMI logs, and BeyondTrust Remote Support logs. After patching (9.1.1.0200, 9.0.2.0200, 8.0 U3m, VCF 5.2.5), rotate the SAML signing certificate, the vCenter master key and database credentials if anything is found. vCenter 7.0 has no public fix.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
