# Encoded and Obfuscated PowerShell Hunt

## Hunt Details

* Type: Lab simulation
* Priority: High
* MITRE ATT&CK Tactics: Execution, Defense Evasion
* MITRE ATT&CK Techniques:
  * T1059.001 - Command and Scripting Interpreter: PowerShell (Execution)
  * T1027 - Obfuscated Files or Information (Defense Evasion)
  * T1105 - Ingress Tool Transfer (Command and Control)
* Attack Stage: Execution and Defense Evasion

## Hunt Hypothesis

Attackers use PowerShell with encoded commands, hidden windows and download-and-run patterns to run code without writing files to disk. If this is happening in the environment, it will show up as PowerShell processes with unusual command-line flags, launched by unexpected parent processes, on hosts where PowerShell is not normally used.

## Data Sources

* Microsoft Defender for Endpoint (DeviceProcessEvents, DeviceNetworkEvents)
* PowerShell script block logging (Event ID 4104), if enabled
* Sysmon process creation events (Event ID 1), if deployed
* Threat intelligence (VirusTotal, AlienVault OTX)

## Hunting Steps

1. Find PowerShell processes with encoded, hidden or bypass flags.
2. Decode the Base64 command lines and read what they do.
3. Check which parent process launched PowerShell.
4. Check network connections made by the same process.
5. Compare against a baseline of normal PowerShell use per host and per user.
6. Filter out known administrative tools and scripts.
7. Investigate what remains.

### Hunting Queries

Encoded, hidden or bypass PowerShell:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "-e ", "-w hidden", "-windowstyle hidden", "-nop", "-noprofile", "bypass")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

Download-and-run patterns:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Invoke-WebRequest", "iwr ", "Invoke-Expression", "IEX", "Net.WebClient")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

Decode the Base64 command (Defender extracts it):

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| extend EncodedPart = extract(@"(?i)-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| where isnotempty(EncodedPart)
| extend Decoded = base64_decode_tostring(EncodedPart)
| project Timestamp, DeviceName, AccountName, Decoded
```

Rare parent processes launching PowerShell:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| summarize Launches = count(), Hosts = dcount(DeviceName) by InitiatingProcessFileName
| where Launches < 10
| order by Launches asc
```

Network connections from PowerShell:

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemoteIPType == "Public"
| summarize Connections = count() by DeviceName, RemoteUrl, RemoteIP
| order by Connections desc
```

## Baseline and Filtering

* Baseline: List which hosts and accounts run PowerShell normally over 30 days. IT admin hosts and management servers usually account for most of it.
* Known-good to exclude: Software deployment tools, monitoring agents, scheduled admin scripts and the security tools that use encoded commands.
* Keep for review: Standard user workstations running encoded or hidden PowerShell, and any PowerShell launched by Office, a browser or a script host.

## Analysis

Results were reviewed in three groups: encoded commands, download-and-run patterns and rare parent processes. Most results came from software deployment and monitoring tools and were added to the allowlist. Three results remained after filtering:

* A finance workstation ran an encoded command launched by a Word process, which decoded to a download of a script from an external host.
* An engineering laptop ran PowerShell with a hidden window and execution policy bypass launched from a user's Downloads folder.
* A service account ran a Base64 command at an odd hour, which turned out to be an approved backup script.

## Findings

Two of the three remaining results were suspicious and escalated, and one was benign. The finance workstation case matched a phishing-delivered macro and was handed to incident response as an investigation, in the same way as the malware execution case. The engineering laptop was a user running a downloaded script, which was a policy issue rather than an attack. The backup script was documented and added to the allowlist.

## Outcome

Status: Suspicious activity found and escalated
Evidence: Process events, decoded command lines and network connection logs

## Detection Conversion

The first query, with an allowlist of known admin hosts and tools, was turned into a scheduled Sentinel analytics rule that alerts on encoded or hidden PowerShell on standard workstations. A second rule alerts when Office applications launch PowerShell.

## Lessons Learned

Encoded commands alone are not enough to call something malicious, because management tools use them too. The signals that matter most are the parent process, the host type and the decoded content. Recommend enabling script block logging so decoded content is available, and using Constrained Language Mode on standard workstations.

## Portfolio Note

This is a simulated hunt. Replace the findings with verified results from your lab before presenting it as a completed hunt.
