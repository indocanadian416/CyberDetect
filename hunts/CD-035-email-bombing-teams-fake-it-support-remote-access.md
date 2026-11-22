# CD-035 · Email Bombing Followed by External Teams "IT Support" and Remote-Access Tools
| | |
|---|---|
| **Hunts for** | The three steps of the mail-bombing / fake help-desk play: (1) one mailbox suddenly receiving hundreds of sign-up and newsletter emails, (2) a one-to-one Teams chat or call from an external tenant with a support-sounding name, (3) Quick Assist or another remote-access tool starting on that user's device shortly after. |
| **Threat / CVE** | Ongoing campaign reported again on Nov 22, 2026 (Hackread) and earlier by Fortra, Arctic Wolf, Unit 42, eSentire and Sophos. Used by ransomware affiliates (Black Basta lineage, STAC5777) to get hands-on access. No CVE. |
| **MITRE ATT&CK** | T1566.004 Spearphishing Voice, T1534 Internal Spearphishing, T1219 Remote Access Software, T1499 (email flooding as a pretext) |
| **Category** | Initial Access / Social Engineering |
| **First published** | 2026-11-22 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
// Step 1: mail-bombed recipients (tune the threshold to your baseline)
EmailEvents
| where Timestamp > ago(7d)
| summarize Mails=count(), Senders=dcount(SenderFromDomain) by RecipientEmailAddress, bin(Timestamp, 1h)
| where Mails > 100 and Senders > 30
| order by Mails desc
```

```kql
// Step 2: external one-to-one Teams chats with support-themed display names
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType in ("ChatCreated","MessageSent","MemberAdded")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("help desk","helpdesk","it support","service desk","it assistance","security team","tech support")
| where Raw has "HasForeignTenantUsers\":true"   // external tenant in the chat
| project Timestamp, AccountDisplayName, ActionType, IPAddress, Raw
```

```kql
// Step 3: remote-access tools within 2 hours of a mail-bomb on the same user
let bombed = EmailEvents
| where Timestamp > ago(7d)
| summarize Mails=count(), Senders=dcount(SenderFromDomain), BombTime=min(Timestamp) by RecipientEmailAddress, bin(Timestamp, 1h)
| where Mails > 100 and Senders > 30
| project Upn=tolower(RecipientEmailAddress), BombTime;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("quickassist.exe","AnyDesk.exe","TeamViewer.exe","ScreenConnect.ClientService.exe","rustdesk.exe","Supremo.exe","AteraAgent.exe","LogMeIn.exe","msra.exe")
| extend Upn = tolower(InitiatingProcessAccountUpn)
| join kind=inner bombed on Upn
| where Timestamp between (BombTime .. BombTime + 2h)
| project Timestamp, DeviceName, Upn, FileName, ProcessCommandLine, BombTime
```

## CrowdStrike Falcon (CQL)

```
// Remote-access tools started interactively (pair the user and time with the email gateway's flood alert)
#event_simpleName=ProcessRollup2
| FileName=/^(quickassist|anydesk|teamviewer|rustdesk|supremo|msra|ateraagent|logmein)\.exe$/i OR FileName=/^ScreenConnect\.ClientService\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

```
// New tools dropped from the browser or Teams right after a Quick Assist session
#event_simpleName=ProcessRollup2 ParentBaseFileName=/^(quickassist|ms-teams|msedge|chrome)\.exe$/i
| FileName=/^(powershell|pwsh|cmd|mshta|rundll32|curl|bitsadmin|msiexec)\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Notes

The Teams `RawEventData` field layout varies by tenant and licence; inspect a few external chats first and adjust the filter. Best mitigations: restrict external Teams access to allow-listed domains, remove or restrict Quick Assist, and tell staff that IT never starts support through an external Teams account. Pair with CD-019 (rogue ScreenConnect service) and CD-003 (new local accounts).

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
