# Kerberoasting Detection

## 1. Detection Summary

**Use Case:** Kerberoasting  
**Platform:** Microsoft Sentinel  
**Data Source:** Windows Security Events  
**Severity:** High  
**MITRE ATT&CK:** T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting

### Description

Detects unusual Kerberos service ticket requests that may indicate an attempt to obtain service tickets for accounts with Service Principal Names (SPNs).

Attackers may request service tickets and attempt to crack the associated service account credentials offline.

---

## 2. Detection Logic

```text
Kerberos Service Ticket Request
        ↓
Service Account / SPN
        ↓
Unusual Request Pattern
        ↓
Source + Account Analysis
        ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4769
| where TicketEncryptionType in ("0x17", "0x18")
| summarize
    TicketRequests = count(),
    Services = dcount(ServiceName),
    ServiceList = make_set(ServiceName, 20)
    by Account, IpAddress
| where TicketRequests >= 10
| project
    Account,
    IpAddress,
    TicketRequests,
    Services,
    ServiceList
| order by TicketRequests desc
```

---

## 4. How It Works

The detection:

1. Monitors Kerberos service ticket requests.
2. Focuses on ticket encryption types commonly associated with Kerberoasting investigations.
3. Groups requests by account and source IP.
4. Identifies unusually high ticket-request activity.
5. Generates candidates for investigation.

The event pattern alone does not confirm Kerberoasting. Account context, SPNs, encryption types, and normal administrative activity should be reviewed.

---

## 5. Investigation

Review:

- Source IP
- Requesting account
- Service account
- SPN
- Number of requested tickets
- Encryption type
- Request timestamps
- Source endpoint
- Process activity
- Recent privilege or account changes

Pay particular attention to a user requesting tickets for multiple service accounts in a short period.

---

## 6. False Positives

Possible legitimate activity:

- Applications using Kerberos
- Service discovery
- Administrative activity
- Monitoring systems
- Automated services
- Domain authentication workflows

Establish normal Kerberos activity for service accounts and administrative systems.

---

## 7. Response

If malicious Kerberoasting activity is confirmed:

1. Identify the requesting account and endpoint.
2. Review the targeted service accounts.
3. Investigate the source process.
4. Search for additional Kerberos ticket requests.
5. Review subsequent authentication activity.
6. Reset affected service-account credentials if required.
7. Investigate possible privilege escalation or lateral movement.

**Detection Goal:** Identify suspicious Kerberos service-ticket activity that may indicate Kerberoasting or credential-access activity.
