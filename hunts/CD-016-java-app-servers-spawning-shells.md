# CD-016 · Java Application Servers Spawning Shells
| | |
|---|---|
| **Hunts for** | Java and Tomcat processes launching shells or download tools, labelled by application (Confluence, Puppet/OpenVox, Apache Roller, Jira, Jenkins, Keycloak). |
| **Threat / CVE** | Apache Axis CVE-2026-90436 (Confluence, N-central), Puppet CVE-2026-115731, Apache Roller CVE-2026-129448, Java4Shell CVE-2026-114938 |
| **MITRE ATT&CK** | T1190; T1059.004 |
| **Category** | Initial Access / Exploitation |
| **First published** | 2026-11-19 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java","java.exe","tomcat9.exe","tomcat10.exe")
| where FileName in~ ("sh","bash","dash","cmd.exe","powershell.exe","curl","wget","whoami","id","nc","python3","perl")
| extend App = case(InitiatingProcessCommandLine has "confluence", "Confluence",
                    InitiatingProcessCommandLine has_any ("puppetserver","puppet-server","openvox"), "Puppet/OpenVox",
                    InitiatingProcessCommandLine has "roller", "Apache Roller",
                    InitiatingProcessCommandLine has "jira", "Jira",
                    InitiatingProcessCommandLine has "jenkins", "Jenkins",
                    InitiatingProcessCommandLine has "keycloak", "Keycloak", "Other Java")
| project Timestamp, DeviceName, App, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=ProcessRollup2 ParentBaseFileName=/^(java|java\.exe|tomcat\d*\.exe)$/i
| FileName=/^(sh|bash|dash|cmd\.exe|powershell\.exe|curl|wget|whoami|id|nc|python3|perl)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

Rapid7 observed Confluence's Java process starting bash and curl after POSTs to /plugins/servlet/soap-axis1/confluenceservice-v2. Also search web/proxy logs for that path.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
