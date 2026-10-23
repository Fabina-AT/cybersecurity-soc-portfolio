# Ransomware Investigation

## Case Details

| Field | Details |
|---|---|
| **Type** | Lab simulation |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1486, T1490, T1204.002, T1059.001 |

## Incident Summary

The SOC received a SentinelOne alert for mass file modification and shadow copy deletion on a user's laptop. Files were being renamed with an unknown extension and ransom notes appeared in several folders. The host was isolated within 10 minutes of the alert, which limited encryption to the local drive and one mapped share folder.

## Investigation

- Reviewed the EDR alert and the process tree on the affected host.
- Identified the process responsible for the file changes and how it was launched.
- Checked for shadow copy deletion and backup tampering.
- Checked network connections for communication with external hosts.
- Checked mapped shares and other hosts for the same activity.
- Analysed the file hash in VirusTotal and Any.Run.

## Detection Queries

### 1. Shadow Copy and Recovery Tampering

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

### 2. Mass File Renames from One Process

```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileRenamed"
| summarize Renamed = count() by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, bin(Timestamp, 5m)
| where Renamed > 200
| order by Renamed desc
```

### 3. Ransom Note Files Created

```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FileName has_any ("readme", "decrypt", "restore", "recover") and FileName endswith ".txt"
| summarize Folders = dcount(FolderPath) by DeviceName, FileName
| where Folders > 10
```

## Timeline

| Time | Event | Evidence Source |
|---|---|---|
| 10:12 | User opened an attachment from a phishing email | Defender for Office 365 |
| 10:14 | Loader executed and dropped a second file in the Temp folder | DeviceFileEvents |
| 10:19 | vssadmin delete shadows run to remove recovery points | DeviceProcessEvents |
| 10:20 | Mass file renaming began with an unknown extension | DeviceFileEvents |
| 10:21 | Ransom notes created in multiple folders | DeviceFileEvents |
| 10:22 | SentinelOne alert raised | SentinelOne |
| 10:32 | Host isolated from the network | SentinelOne |

## Findings

The behaviour matched ransomware: shadow copies were deleted first, then more than 200 files were renamed within minutes and ransom notes were dropped. The initial access was a phishing attachment, and the file hash was flagged as ransomware by several vendors. No lateral movement was found, but one mapped share folder was partly encrypted. Root cause: user execution of a malicious attachment, with the file share open to the user's account.

## Response

- Isolated the host immediately using the EDR.
- Disabled the user's account and revoked all sessions.
- Killed the malicious process and kept the host powered on for forensics, with a memory image taken.
- Checked the file share and removed the user's write access.
- Blocked the file hash, domain and IP, and purged the email from other mailboxes.
- Confirmed backups were not affected, then restored the encrypted share folder from backup.
- Rebuilt the laptop from a clean image before returning it to the user.
- Monitored the user's account and the file server for 7 days.

Outcome

Status: Contained, files restored from backup

Evidence: EDR process tree, file event logs, email logs, sandbox report and backup restore record

Lessons Learned

The speed of isolation limited the damage. Recommend a high-severity detection on shadow copy deletion, least-privilege access on shared folders, immutable offline backups, and attack surface reduction rules to block executable content from email. Run a restore test on a regular schedule so recovery time is known.

IOCs

File: Invoice_Payment.zip - phishing attachment

SHA256: <sha256-of-ransomware-sample> - replace with the hash from your lab

Extension: .locked2026 - appended to encrypted files

File: README_RESTORE.txt - ransom note

IP: 203.0.113.99 - external host contacted

Command: vssadmin delete shadows /all /quiet - recovery tampering

Portfolio Note

This is a simulated case study. Replace the figures, times and findings with verified results from your lab before presenting it as a completed investigation.
