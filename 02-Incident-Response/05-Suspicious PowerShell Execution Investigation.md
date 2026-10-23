# Suspicious PowerShell Execution Investigation

## Case Details

| Field | Details |
|---|---|
| **Type** | Lab simulation |
| **Severity** | High |
| **MITRE ATT&CK** | T1059.001, T1027, T1105, T1218 |

## Incident Summary

The SOC received a Microsoft Defender alert for PowerShell running with an encoded command and a hidden window on a user's workstation. The command downloaded and ran content from an external host in memory. The activity was confirmed as malicious, the host was isolated and no persistence or lateral movement was found.

## Investigation

- Reviewed the alert, the process tree and the parent process that launched PowerShell.
- Decoded the Base64 command line to read what it ran.
- Checked the URL and IP in the command in VirusTotal and AlienVault OTX.
- Checked whether the user or a management tool normally runs PowerShell on this host.
- Checked for persistence such as scheduled tasks, run keys and startup folder entries.
- Searched other hosts for the same command pattern and destination.

## Detection Queries

### 1. Encoded or Hidden PowerShell

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden", "-nop", "bypass")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

### 2. PowerShell Download Behaviour

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Invoke-WebRequest", "iwr ", "IEX", "Invoke-Expression")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### 3. Network Connections from PowerShell

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort
```

### 4. Persistence Check

```kql
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKey has @"CurrentVersion\Run"
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

## Timeline

| Time | Event | Evidence Source |
|---|---|---|
| 13:05 | User opened a shortcut file from a downloaded archive | DeviceFileEvents |
| 13:05 | cmd.exe launched PowerShell with an encoded command and hidden window | DeviceProcessEvents |
| 13:06 | PowerShell connected to 203.0.113.120 and pulled a script | DeviceNetworkEvents |
| 13:06 | Script ran in memory with Invoke-Expression, no file written | DeviceProcessEvents |
| 13:10 | Defender alert raised | Microsoft Defender |
| 13:25 | Host isolated | Microsoft Defender |

## Findings

The decoded command used a bypass of the execution policy, a hidden window and a download-and-run pattern with Invoke-Expression, which is typical of fileless malware. The destination IP was flagged as malicious by several vendors. The user did not normally run PowerShell, and no admin tool explained it. No persistence was found and no other host showed the same command or destination. Root cause: a user ran a malicious shortcut from a downloaded archive.

## Response

- Isolated the host using the EDR.
- Killed the PowerShell process and the parent process chain.
- Blocked the destination IP and domain.
- Reset the user's password as a precaution and revoked sessions.
- Scanned the host, removed the downloaded archive and returned the host to the network.
- Monitored the host and account for 72 hours.

## Outcome

- **Status:** Contained, no persistence or lateral movement found
- **Evidence:** EDR process tree, decoded command line, network logs and threat intelligence results

## Lessons Learned

Encoded commands, hidden windows and download-and-run patterns in PowerShell are high-confidence signals when the user has no admin role. Recommend enabling PowerShell script block logging, using Constrained Language Mode on standard workstations, and keeping the first query as a scheduled detection with an allowlist for known admin tools.

## IOCs

- **Process:** `powershell.exe -nop -w hidden -enc` - encoded hidden command
- **Pattern:** `IEX (New-Object Net.WebClient).DownloadString` - download and run in memory
- **IP:** `203.0.113.120` - script host
- **File:** `Report_Q3.zip` - archive containing the malicious shortcut

## Portfolio Note

This is a simulated case study. Replace the figures, times and findings with verified results from your lab before presenting it as a completed investigation.
