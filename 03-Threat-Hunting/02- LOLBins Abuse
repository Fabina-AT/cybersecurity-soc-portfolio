# Hunt 2: LOLBins Abuse

## Hunt Objective

Identify suspicious usage of legitimate Windows utilities such as certutil, mshta, rundll32, regsvr32, and bitsadmin that may indicate malicious execution, payload downloads, or defense evasion.

## Hunting Hypothesis

Attackers may abuse built-in Windows utilities to download malicious files, execute scripts, load suspicious DLLs, and communicate with external servers while avoiding detection.

## Data Sources

- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Sysmon (Event ID 1 – Process Creation, Event ID 3 – Network Connection)
- Windows Security Events (Event ID 4688)

## 1. Suspicious LOLBins Execution

Hunt for suspicious command-line arguments used by commonly abused Windows binaries.

**Microsoft Sentinel – KQL**

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "certutil.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bitsadmin.exe"
)
| where ProcessCommandLine has_any (
    "http://",
    "https://",
    "-urlcache",
    "-decode",
    "javascript:",
    "vbscript:",
    "scrobj.dll",
    "Download",
    "/transfer",
    "Start-BitsTransfer"
)
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          SHA256
| order by Timestamp desc
```

## 2. External Connections from LOLBins

Hunt for built-in Windows utilities communicating with public IP addresses.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "certutil.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bitsadmin.exe"
)
| where RemoteIPType == "Public"
| project Timestamp,
          DeviceName,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          RemoteIP,
          RemoteUrl,
          RemotePort,
          Protocol
| order by Timestamp desc
```

**Investigation Focus**

- Identify external IP addresses and domains.
- Check destination reputation using VirusTotal.
- Review the command line used by the binary.
- Identify downloaded files and their hashes.
- Check whether the destination is associated with known malicious infrastructure.

## 3. LOLBins Launched by Unusual Parent Processes

Hunt for LOLBins launched by unexpected applications, such as Office applications, browsers, PDF readers, or script interpreters.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "certutil.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bitsadmin.exe"
)
| where InitiatingProcessFileName !in~ (
    "explorer.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "services.exe",
    "svchost.exe"
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

- Identify the parent process launching the LOLBin.
- Review the parent and child process command lines.
- Investigate Office applications, browsers, and script hosts.
- Check whether the binary was launched from an unusual directory.
- Correlate with network connections and downloaded files.

## MITRE ATT&CK Mapping

- T1218 – System Binary Proxy Execution
- T1105 – Ingress Tool Transfer
- T1059 – Command and Scripting Interpreter
- T1071.001 – Web Protocols
- T1027 – Obfuscated Files or Information

## Investigation Steps

1. Identify the affected device and user account.
2. Review the LOLBin command-line arguments.
3. Investigate the parent process and process tree.
4. Check external network connections.
5. Analyze downloaded files and file hashes.
6. Review related EDR alerts and endpoint activity.
7. Determine whether the activity is legitimate or malicious.

## False Positives

- Legitimate Windows administration.
- Software installation and updates.
- IT troubleshooting activities.
- Approved script execution.
- Enterprise software deployment tools.

## Response Actions

- Isolate the endpoint if malicious activity is confirmed.
- Terminate malicious processes.
- Block confirmed malicious IP addresses and domains.
- Quarantine malicious files.
- Investigate possible persistence and lateral movement.
- Escalate according to SOC incident response procedures.

## Hunting Conclusion

Document the LOLBin involved, command-line arguments, parent process, external connections, affected devices, investigation evidence, and final findings.

Possible outcomes:

- No suspicious activity found.
- Benign administrative activity.
- Suspicious activity requiring further investigation.
- Confirmed malicious activity.
