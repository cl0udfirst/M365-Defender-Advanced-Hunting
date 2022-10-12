# Powershell execution with BASE64 Encoded String

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has "-e"
| project Timestamp, DeviceName, DeviceId, ReportId, InitiatingProcessCommandLine
| top 100 by Timestamp
```
---------

## Category 

Defense evasion

## MITRE techniques

T1027: Obfuscated Files or Information

