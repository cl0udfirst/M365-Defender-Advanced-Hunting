# Collection of M365 Defender Advanced Hunting querys

### Powershell execution with base64 encoded string

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has "-e"
| project Timestamp, DeviceName, DeviceId, ReportId, InitiatingProcessCommandLine
| top 100 by Timestamp
```

-----------

### Detect Impacket WMIexec usage on a device

```
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all (@" 1> \127.0.0.1\", "/Q ", "/c ", @" 2>&1")
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
```

### This query has the same purpose as above, but it also groups all the commands launched using Impacket WMIexec on the device:

```
| where Timestamp >= ago(7d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all (@" 1> \127.0.0.1\", "/Q ", "/c ", @" 2>&1")
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| project DeviceName, DeviceId, Timestamp, ProcessCommandLine
| summarize make_set(ProcessCommandLine), min(Timestamp), max(Timestamp) by DeviceId, DeviceName
```
-----------

## Querying attempts to dump the LSASS process memory comsvcs.dll:

let startTime = ago(7d);
let endTime = now();
DeviceProcessEvents
| where Timestamp between (startTime..endTime)
| where FileName =~ 'rundll32.exe'
and ProcessCommandLine has 'comsvcs.dll'
and ProcessCommandLine has_any ('full','MiniDump')
| where not (ProcessCommandLine matches regex @'{[\w\d]{8}-[\w\d]{4}-[\w\d]{4}-[\w\d]{4}-[\w\d]{12}}'
and ProcessCommandLine matches regex @'(\d{2}_){3}' )

------------
