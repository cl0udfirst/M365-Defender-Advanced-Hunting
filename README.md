# Collection of M365 Defender Advanced Hunting querys

## Powershell execution with base64 encoded string

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has "-e"
| project Timestamp, DeviceName, DeviceId, ReportId, InitiatingProcessCommandLine
| top 100 by Timestamp
```

-----------

## Detect Impacket WMIexec usage on a device

```
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all (@" 1> \127.0.0.1\", "/Q ", "/c ", @" 2>&1")
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
```

# This query has the same purpose as above, but it also groups all the commands launched using Impacket WMIexec on the device:

```
| where Timestamp >= ago(7d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all (@" 1> \127.0.0.1\", "/Q ", "/c ", @" 2>&1")
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| project DeviceName, DeviceId, Timestamp, ProcessCommandLine
| summarize make_set(ProcessCommandLine), min(Timestamp), max(Timestamp) by DeviceId, DeviceName
```
-----------

