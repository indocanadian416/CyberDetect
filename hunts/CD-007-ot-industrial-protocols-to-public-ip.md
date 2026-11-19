# CD-007 · OT: Industrial Protocols Going to Public IPs
| | |
|---|---|
| **Hunts for** | Endpoints talking S7comm (102), Modbus (502) or EtherNet/IP (44818, 2222) to internet addresses. Finds exposed PLCs, engineering workstations reaching out, or misrouted OT traffic. |
| **Threat / CVE** | Iranian PLC targeting (AA26-097A); PHP2Shell in OT products |
| **MITRE ATT&CK** | T1190; T0883 Internet Accessible Device (ICS) |
| **Category** | OT / ICS |
| **First published** | 2026-11-11 (Daily Threat Review: Energy and Mining) |

## Microsoft Defender XDR (KQL)

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (102, 502, 44818, 2222) and RemoteIPType == "Public"
| summarize Conns=count(), Dests=make_set(RemoteIP, 10) by DeviceName, InitiatingProcessFileName, RemotePort
```

## CrowdStrike Falcon (CQL)

```
#event_simpleName=NetworkConnectIP4 (RemotePort=102 OR RemotePort=502 OR RemotePort=44818 OR RemotePort=2222)
| cidr(field=RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"], negate=true)
| join(query={#data_source_name=aidmaster | groupBy([aid], function=selectLast([ComputerName]))}, field=[aid], include=[ComputerName])
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=count())
```

## Notes

A hit means an OT device or workstation is talking to the internet. Involve your OT team. The CrowdStrike query is the Nov 11 v2 version (aidmaster join for host names); it replaces the first draft, which grouped by a process name that network events do not carry.

> Test in your own environment before relying on this query. CrowdStrike field names should be confirmed in your Falcon console.
