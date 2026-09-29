# Silver Ticket Detection

## 1. Detection Summary

**Use Case:** Silver Ticket  
**Platform:** Microsoft Sentinel  
**Data Source:** Windows Security Events  
**Severity:** High  
**MITRE ATT&CK:** T1558.002 – Silver Ticket

### Description

Detects suspicious Kerberos service-ticket activity that may indicate the use of a forged Silver Ticket.

A Silver Ticket is a forged **Kerberos service ticket (TGS)** created using a compromised service account credential.

---

## 2. Detection Logic

```text
Kerberos Activity
      ↓
4768 / 4769
      ↓
Review TGT / Service Ticket Activity
      ↓
Unexpected Service or Source
      ↓
Investigate Missing / Unusual Ticket Pattern
      ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID in (4768, 4769)
| summarize
    Requests = count(),
    SourceIPs = make_set(IpAddress, 10),
    Services = make_set(ServiceName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account, Computer, EventID
| where Requests >= 5
| project
    Account,
    Computer,
    EventID,
    Requests,
    SourceIPs,
    Services,
    FirstSeen,
    LastSeen
| order by Requests desc
```

---

## 4. Event IDs

| Event ID | Meaning |
|---|---|
| **4768** | Kerberos TGT requested |
| **4769** | Kerberos service ticket (TGS) requested |

**4769 is particularly important for Silver Ticket investigations** because Silver Tickets are forged service tickets.

---

## 5. How It Works

The detection:

1. Monitors Kerberos events **4768 and 4769**.
2. Groups activity by account and computer.
3. Counts ticket requests.
4. Records source IPs and requested services.
5. Highlights accounts with repeated Kerberos activity.
6. Analysts then investigate whether the ticket pattern is legitimate.

A missing or unusual 4768 → 4769 sequence can be an investigation clue, but it does **not automatically confirm a Silver Ticket**.

---

## 6. Investigation

Review:

- Account
- Source IP
- Source computer
- Destination computer
- Service name
- Event ID
- Authentication timeline
- 4768 activity
- 4769 activity
- Service account
- SPN
- Recent credential changes
- Other lateral-movement activity

### Example

```text
4768
 ↓
TGT requested
 ↓
4769
 ↓
Service ticket requested
 ↓
Service accessed
```

If a service is accessed with unusual **4769** activity and the expected Kerberos authentication sequence is missing or abnormal, investigate for possible forged-ticket usage.

---

## 7. False Positives

Possible legitimate activity:

- Application servers
- Service accounts
- Database services
- Scheduled tasks
- Monitoring systems
- Normal Kerberos authentication

Establish a baseline for expected service-account and application activity.

---

## 8. Response

If Silver Ticket activity is suspected:

1. Identify the affected service account.
2. Identify the source host.
3. Review the associated SPN.
4. Correlate 4768 and 4769 events.
5. Investigate the service-account credential.
6. Review lateral-movement activity.
7. Protect or reset the affected service-account credential according to incident procedures.
8. Continue hunting for additional forged-ticket activity.

**Detection Goal:** Identify abnormal Kerberos service-ticket activity that may indicate Silver Ticket usage or service-account compromise.
