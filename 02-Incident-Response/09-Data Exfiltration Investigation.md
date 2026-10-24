# Data Exfiltration Investigation

## Case Details

| Field | Details |
|---|---|
| **Type** | Lab simulation |
| **Severity** | High |
| **MITRE ATT&CK Tactics** | Collection, Exfiltration |
| **Attack Stage** | Collection to Exfiltration |

### MITRE ATT&CK Techniques

- **T1074** - Data Staged (Collection)
- **T1567.002** - Exfiltration Over Web Service: Exfiltration to Cloud Storage (Exfiltration)
- **T1048** - Exfiltration Over Alternative Protocol (Exfiltration)
- **T1052** - Exfiltration Over Physical Medium (Exfiltration)

## Incident Summary

The SOC received a Forcepoint DLP alert for a large upload of files containing customer data to a personal cloud storage site. The user was an employee who had resigned two weeks earlier. The investigation confirmed the transfer, identified the files involved and escalated the case to HR and legal. The account was restricted before further uploads took place.

## Investigation

- Reviewed the DLP alert, the policy that triggered and the data classification of the files.
- Identified the user, the device, the destination and the volume of data sent.
- Checked proxy and firewall logs for other uploads or unusual destinations.
- Checked endpoint activity for file archiving, USB use and email forwarding.
- Compared the activity with the user's normal behaviour over the last 30 days.
- Checked HR context, such as notice period and access that was still active.

## Detection Queries

### 1. Large Uploads to Personal Cloud Storage

```kql id="m4x8qa"
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor in ("Fortinet", "Palo Alto Networks")
| where RequestURL has_any ("drive.google.com", "dropbox.com", "mega.nz", "wetransfer.com", "onedrive.live.com")
| summarize UploadedMB = sum(SentBytes) / 1048576.0, Requests = count() by SourceUserName, SourceIP, DestinationHostName
| where UploadedMB > 100
| order by UploadedMB desc
```

### 2. Files Copied to Removable Media

```kql id="n6b2wr"
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FolderPath startswith "D:\\" or FolderPath startswith "E:\\"
| summarize Files = count() by DeviceName, InitiatingProcessAccountName
| where Files > 100
```

### 3. Archive Creation Before the Upload

```kql id="p9c3vf"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where AccountName == "user.exemployee"
| where ProcessCommandLine has_any ("7z", "rar", "zip", "Compress-Archive")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### 4. Comparison with the User's Normal Upload Volume

```kql id="w5r7kd"
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where SourceUserName == "user.exemployee"
| summarize DailyMB = sum(SentBytes) / 1048576.0 by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

## Timeline

| Time | Event | Evidence Source |
|---|---|---|
| 3 weeks before | User submitted resignation, notice period started | HR record |
| 17:30 | User searched and opened the customer database export folder | DeviceFileEvents |
| 17:42 | 1,200 files copied into a single archive on the desktop | DeviceProcessEvents |
| 17:55 | Archive uploaded to a personal cloud storage site, about 850 MB | Fortinet logs |
| 17:56 | Forcepoint DLP alert raised for customer data leaving the network | Forcepoint DLP |
| 18:20 | SOC confirmed the transfer and escalated to HR and legal | Ticket |
| 18:45 | Account restricted and device isolated | Defender |

## Findings

The user's normal daily upload volume was under 20 MB, so an 850 MB upload to a personal storage site stood out. The archive contained customer records classified as confidential. The access was within the user's role, so there was no unauthorised access, but the transfer to a personal destination broke the data handling policy. No USB use or email forwarding was found. Root cause: an insider with legitimate access copying data during a notice period, with no restriction on uploads to personal cloud services.

## Response

- Restricted the account and disabled access to the data share.
- Isolated the device and preserved it for forensic review.
- Blocked the destination site for the user and checked for other users uploading to it.
- Documented the files, volumes and timestamps and handed the evidence to HR and legal.
- Requested the deletion of the uploaded data through legal channels.
- Reviewed the customer data involved to support the data breach assessment.
- Monitored for related activity for 30 days.

## Outcome

- **Status:** Contained, escalated to HR and legal
- **Evidence:** DLP alert, proxy logs, endpoint file events and archive creation records

## Lessons Learned

Users who are leaving should have monitored access and tighter controls. Recommend a DLP block (not only alert) on customer data to personal cloud storage, blocking personal cloud sites at the proxy, alerting on large uploads and archive creation, and a process where HR tells security when someone resigns.

## IOCs

- **User:** `user.exemployee` - insider involved
- **Destination:** Personal cloud storage site - upload target
- **File:** `customer_export_archive.zip` - archive of customer data, about 850 MB
- **Behaviour:** Large archive creation followed by upload within 15 minutes - exfiltration pattern

## Portfolio Note

This is a simulated case study. Replace the figures, times and findings with verified results from your lab before presenting it as a completed investigation.
