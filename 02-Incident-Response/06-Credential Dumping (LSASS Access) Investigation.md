# Credential Dumping (LSASS Access) Investigation

## Case Details

| Field            | Details                     |
| ---------------- | --------------------------- |
| **Type**         | Lab simulation              |
| **Severity**     | Critical                    |
| **MITRE ATT&CK** | T1003.001, T1059.001, T1078 |

## Incident Summary

The SOC received a Microsoft Defender alert for suspicious access to the LSASS process on a server. A process running from a user's temp folder opened LSASS memory and wrote a dump file. The host was isolated, the exposed accounts were reset and no use of the stolen credentials was found on other systems.

## Investigation

- Reviewed the alert and identified the process that accessed LSASS and its parent process.
- Checked whether the process was a known security or admin tool.
- Checked for a memory dump file and whether it was copied off the host.
- Identified which accounts were logged on to the host at the time.
- Checked sign-in activity for those accounts after the event, looking for use from other hosts.
- Checked how the attacker first gained access to the host.

## Detection Queries

### 1. Process Accessing LSASS

```kql
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe", "csrss.exe", "wininit.exe", "svchost.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

### 2. LSASS Dump Through Built-in Tools

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("comsvcs.dll", "MiniDump", "procdump", "lsass")
| where ProcessCommandLine has_any ("-ma", "MiniDump", "dump")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### 3. Dump File Creation

```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FileName endswith ".dmp" or FileName has "lsass"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```

### 4. Use of Exposed Accounts from Other Hosts

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where AccountName in ("svc-backup", "adm-user01")
| where ActionType == "LogonSuccess"
| summarize Hosts = dcount(DeviceName), Logons = count() by AccountName, RemoteIP
| order by Hosts desc
```

## Timeline

| Time  | Event                                                  | Evidence Source     |
| ----- | ------------------------------------------------------ | ------------------- |
| 15:02 | Suspicious executable ran from the user's Temp folder  | DeviceProcessEvents |
| 15:03 | Process opened LSASS memory with a read access request | DeviceEvents        |
| 15:03 | Dump file created in the Temp folder                   | DeviceFileEvents    |
| 15:05 | Defender alert raised                                  | Microsoft Defender  |
| 15:12 | Dump file archived and sent to an external IP          | DeviceNetworkEvents |
| 15:20 | Host isolated                                          | Microsoft Defender  |

## Findings

An unsigned executable in a temp folder opened LSASS with memory read access and wrote a dump file, which is not normal behaviour for any approved tool on this server. The file was then sent to an external IP. Two accounts were logged on at the time, one of them a service account. No successful logons from unusual hosts were seen for either account after the event. Root cause: an attacker with an existing foothold on the server, which was traced back to a user who had run a malicious file earlier that day.

## Response

- Isolated the host using the EDR.
- Killed the process and removed the dump file and the executable.
- Reset passwords for both exposed accounts and revoked their sessions.
- Rotated the service account credentials and updated the services that use them.
- Blocked the external IP and the file hash.
- Reviewed sign-in logs for both accounts across the estate for 7 days.
- Monitored the server and accounts for 14 days.

## Outcome

- **Status:** Contained, no use of stolen credentials found
- **Evidence:** EDR alert and process tree, file event logs, network logs and sign-in records

## Lessons Learned

Any process outside the approved security tools that opens LSASS should be treated as high risk. Recommend enabling LSA protection and Credential Guard, turning on the attack surface reduction rule that blocks credential stealing from LSASS, limiting where privileged and service accounts can log on, and keeping the first query as a scheduled detection.

## IOCs

- **Process:** Unsigned executable in the user's Temp folder - accessed LSASS memory
- **File:** `lsass.dmp` - memory dump created on the host
- **IP:** `203.0.113.150` - destination of the dump file
  - **SHA256:** `<sha256-of-executable>` 

## Portfolio Note

This is a simulated case study. Replace the figures, times and findings with verified results from your lab before presenting it as a completed investigation.
