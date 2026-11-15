# Hunt 1: Suspicious PowerShell Execution

## Hunt Objective

Identify suspicious PowerShell execution, unusual parent-child process relationships, and external network connections that may indicate malware execution, payload downloads, or command-and-control activity.

## Hunting Hypothesis

Attackers may abuse PowerShell to execute encoded commands, download malicious payloads, communicate with external servers, or launch scripts through unusual parent processes.

## Data Sources

- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Sysmon (Event ID 1 – Process Creation, Event ID 3 – Network Connection)
- Windows Security Events (Event ID 4688)

## 1. Encoded and Obfuscated PowerShell Execution

Hunt for encoded commands, hidden windows, execution policy bypass, and suspicious scripting methods.

**Microsoft Sentinel – KQL**

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-EncodedCommand",
    "-enc",
    "-WindowStyle Hidden",
    "-ExecutionPolicy Bypass",
    "DownloadString",
    "DownloadFile",
    "FromBase64String",
    "Invoke-Expression"
)
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

## 2. External Connections from PowerShell

Hunt for PowerShell processes communicating with public IP addresses and external destinations.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe"
)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          RemoteIP, RemoteUrl, RemotePort,
          Protocol
| order by Timestamp desc
```

**Investigation Focus**

- Identify external IP addresses and domains.
- Check destination reputation using VirusTotal.
- Review connection frequency and timing.
- Investigate possible payload downloads or data transfers.
- Correlate network activity with PowerShell execution.

## 3. Unusual Parent Process Launching PowerShell

Hunt for unexpected applications or processes launching PowerShell.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where InitiatingProcessFileName !in~ (
    "explorer.exe",
    "cmd.exe",
    "services.exe",
    "svchost.exe",
    "powershell.exe",
    "pwsh.exe"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

**Investigation Focus**

- Identify the parent process launching PowerShell.
- Review the parent process command line and file path.
- Investigate Office applications, browsers, PDF readers, and script hosts.
- Check whether the parent process is expected to launch PowerShell.
- Correlate with network connections and subsequent process execution.

## MITRE ATT&CK Mapping

- T1059.001 – PowerShell
- T1027 – Obfuscated Files or Information
- T1105 – Ingress Tool Transfer
- T1071.001 – Web Protocols
- T1204.002 – Malicious File

## Investigation Steps

1. Identify the affected device and user account.
2. Review PowerShell command-line arguments.
3. Investigate the parent process and process tree.
4. Identify external IP addresses and domains contacted.
5. Check downloaded files, hashes, and network activity.
6. Correlate findings with EDR alerts and other endpoint events.
7. Determine whether the activity is legitimate or malicious.

## False Positives20.

- Authorized PowerShell automation.
- IT administration scripts.
- Software installation and updates.
- Monitoring and configuration management tools.
- Approved external API connections.

## Response Actions

- Isolate the endpoint if compromise is confirmed.
- Terminate malicious processes.
- Block confirmed malicious IP addresses and domains.
- Remove malicious scripts and payloads.
- Reset compromised credentials if necessary.
- Escalate according to SOC incident response procedures.

## Hunting Conclusion

Document the PowerShell commands, parent process, external connections, affected devices, investigation evidence, and final findings.

Possible outcomes:

- No suspicious activity found.
- Benign administrative activity.
- Suspicious activity requiring further investigation.
- Confirmed malicious activity.
