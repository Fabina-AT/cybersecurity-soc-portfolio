# Golden Ticket Detection

## 1. Detection Summary

**Use Case:** Golden Ticket  
**Platform:** Microsoft Sentinel  
**Data Source:** Windows Security Events  
**Severity:** Critical  
**MITRE ATT&CK:** T1558.001 – Golden Ticket

### Description

Detects suspicious Kerberos authentication activity that may indicate the use of forged Kerberos Ticket Granting Tickets (TGTs).

A Golden Ticket attack typically requires compromise of the **KRBTGT account** or its secret material. An attacker can then forge Kerberos tickets and attempt to access domain resources.

---

## 2. Detection Logic

```text
Kerberos Authentication
        ↓
Unusual Account / Ticket Activity
        ↓
Unexpected Source Host
        ↓
Abnormal Ticket Lifetime / Timing
        ↓
Correlate Account Activity
        ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4624
| where LogonType == 3
| summarize
    Logons = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SourceIPs = make_set(IpAddress, 10)
    by Account, Computer
| where Logons >= 10
| project
    Account,
    Computer,
    Logons,
    SourceIPs,
    FirstSeen,
    LastSeen
| order by Logons desc
```

---

## 4. How It Works

Golden Ticket detection is difficult because a forged Kerberos ticket can appear similar to legitimate authentication.

The detection therefore looks for **unusual authentication patterns** and should be correlated with other Active Directory activity.

Important investigation indicators include:

- Unusual source computer
- Unusual account activity
- Unexpected privileged access
- Abnormal authentication times
- Authentication to multiple systems
- Previous KRBTGT or domain compromise indicators

---

## 5. Investigation

Review:

- User/account
- Source IP
- Source computer
- Destination computer
- Authentication timestamp
- Logon type
- Privilege level
- Kerberos activity
- Account group membership
- Recent DCSync activity
- Recent domain-controller activity

Pay particular attention when unusual authentication follows a suspected **DCSync** or domain-level credential compromise.

---

## 6. False Positives

Possible legitimate activity:

- Domain administrators
- Service accounts
- Application servers
- Scheduled services
- Management systems
- Automated authentication

Establish normal authentication patterns for privileged and service accounts.

---

## 7. Response

If Golden Ticket activity is suspected:

1. Identify the affected accounts and systems.
2. Investigate the source of the authentication.
3. Search for DCSync or other credential-access activity.
4. Investigate compromise of privileged accounts.
5. Follow the organization's domain-containment procedure.
6. Reset the KRBTGT account according to Microsoft-supported procedures.
7. Investigate persistence and lateral movement.
8. Review the environment for additional forged-ticket activity.

**Detection Goal:** Identify abnormal Kerberos authentication patterns that may indicate forged ticket usage following domain-level credential compromise.
