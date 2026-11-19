# CD-015 · AWS: Third-Party Role Assumption (Qubole Supply Chain)
| | |
|---|---|
| **Hunts for** | AssumeRole calls from or naming Qubole, to find customer-created vendor roles that were used to steal files, secrets and identity-provider credentials. |
| **Threat / CVE** | Qubole AWS credential abuse (Oct 14-26, 2026) |
| **MITRE ATT&CK** | T1199 Trusted Relationship; T1078.004 |
| **Category** | Cloud / Supply Chain |
| **First published** | 2026-11-12 (Daily Threat Review: Energy and Mining) |

## Microsoft Sentinel (KQL, AWS CloudTrail connector)

```kql
AWSCloudTrail
| where TimeGenerated > datetime(2026-10-01)
| where EventName == "AssumeRole"
| where RequestParameters contains "qubole" or UserIdentityArn contains "qubole"
| summarize Calls=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SourceIpAddress, UserIdentityAccountId, RecipientAccountId
| order by LastSeen desc
```

## CrowdStrike Falcon (CQL)

Not applicable: Falcon endpoint telemetry does not carry this data. See notes.

## Notes

Needs the AWS CloudTrail connector in Sentinel; this table is not in Defender endpoint data. CrowdStrike endpoint telemetry does not cover AWS role assumption. Remove unused third-party IAM roles.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
