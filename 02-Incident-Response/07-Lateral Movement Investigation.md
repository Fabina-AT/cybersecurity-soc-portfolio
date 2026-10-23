# Lateral Movement Investigation

## Case Details

| Field | Details |
|---|---|
| **Type** | Lab simulation |
| **Severity** | High |
| **MITRE ATT&CK** | T1021.001, T1021.002, T1021.006, T1078 |

## Incident Summary

The SOC received a Microsoft Sentinel alert for a user account signing in over RDP to several servers it had never accessed before, outside working hours. The account had been exposed earlier in the day. The investigation confirmed the account was being used to move between hosts, and the activity was stopped after it reached three servers.

## Investigation

- Reviewed the alert and the account, source host and destination hosts involved.
- Checked whether the account normally logs on to these servers.
- Identified the logon types and protocols used (RDP, SMB or WinRM).
- Built a timeline of every host the account touched.
- Checked what ran on each destination host after the logon.
- Checked how the account was first compromised.

## Detection Queries

### 1. Remote Logons Across Many Hosts

```kql id="l9d2mx"
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive", "Network")
| summarize Hosts = dcount(DeviceName), HostList = make_set(DeviceName) by AccountName, RemoteIP
| where Hosts >= 3
| order by Hosts desc
```

### 2. RDP Logons Outside Working Hours (Windows Security Event 4624, Logon Type 10)

```kql id="y3k8pw"
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624 and LogonType == 10
| where hourofday(TimeGenerated) !between (6 .. 20)
| project TimeGenerated, Computer, Account, IpAddress
```

### 3. Commands Run on Destination Hosts After the Logon

```kql id="b7v4qn"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where AccountName == "adm-user01"
| where DeviceName in ("SRV-APP01", "SRV-FILE01", "SRV-DB01")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

### 4. Admin Shares and Remote Service Creation

```kql id="k2m6rx"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("\\\\", "ADMIN$", "C$", "sc.exe", "psexec", "winrs")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Timeline

| Time | Event | Evidence Source |
|---|---|---|
| 20:40 | Account adm-user01 exposed on a workstation | DeviceEvents |
| 22:10 | RDP logon from the workstation to SRV-APP01 | SecurityEvent |
| 22:25 | Network logon from SRV-APP01 to SRV-FILE01 | DeviceLogonEvents |
| 22:40 | RDP logon from SRV-FILE01 to SRV-DB01 | SecurityEvent |
| 22:52 | Sentinel alert raised for multi-host remote logons | Sentinel |
| 23:10 | Account disabled and hosts isolated | Defender |

## Findings

The account had never logged on to these three servers before, and the logons happened in a chain, each new hop starting from the previous host. The logons were outside working hours and used RDP and network logons, with admin share access on the file server. No data transfer or malicious tools were found on the first two servers, and the database server was reached only minutes before containment. Root cause: a privileged account exposed on a workstation and then reused from there, with no restriction on where it could log on.

## Response

- Disabled the account and revoked all sessions.
- Isolated the three servers and the source workstation.
- Reset the password and reviewed other privileged accounts that logged on to the workstation.
- Checked the three servers for new accounts, services, scheduled tasks and tools, and found none.
- Blocked RDP from workstations to servers at the firewall.
- Restored normal access once the hosts were verified clean.
- Monitored the accounts and servers for 14 days.

## Outcome

- **Status:** Contained, no data loss or persistence found
- **Evidence:** Logon event logs, EDR process data and sign-in records

## Lessons Learned

Privileged accounts should never log on to workstations, and servers should only accept remote logons from a jump host. Recommend tiered administration, restricting RDP between workstations and servers, requiring MFA for remote admin access, and keeping the first query as a scheduled detection with an allowlist for known admin hosts.

## IOCs

- **Account:** `adm-user01` - privileged account used for movement
- **Source host:** `WKS-0457` - first host, where the account was exposed
- **Destination hosts:** `SRV-APP01`, `SRV-FILE01`, `SRV-DB01` - hosts accessed
- **Protocols:** RDP (3389) and SMB (445) - remote access methods used

## Portfolio Note

This is a simulated case study. Replace the figures, times and findings with verified results from your lab before presenting it as a completed investigation.
