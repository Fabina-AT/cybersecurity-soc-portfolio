# High-Volume DNS Queries Detection

## 1. Detection Summary

**Use Case:** High-Volume DNS Queries
**Platform:** Microsoft Sentinel
**Data Source:** DNS Logs
**Severity:** Medium
**MITRE ATT&CK:** T1071.004 – DNS

### Description

Detects endpoints generating an unusually high number of DNS queries within a short period.

This can indicate malware activity, automated reconnaissance, or abnormal application behavior.

---

## 2. Detection Logic

```text
Endpoint
    ↓
High DNS Query Volume
    ↓
Compare Activity Pattern
    ↓
Identify Abnormal Source
    ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
DnsEvents
| where TimeGenerated >= ago(15m)
| summarize
    Queries = count(),
    UniqueDomains = dcount(Name)
    by ClientIP
| where Queries >= 500
| project
    ClientIP,
    Queries,
    UniqueDomains
| order by Queries desc
```

---

## 4. How It Works

The detection identifies endpoints generating **500 or more DNS queries within 15 minutes**.

A high query count combined with many unique domains can indicate automated or suspicious activity.

---

## 5. Investigation

Review:

* Source endpoint
* User
* Query volume
* Unique domains
* Queried domains
* DNS record types
* Process generating DNS requests
* Related network connections
* Endpoint security alerts

---

## 6. False Positives

Possible legitimate sources:

* DNS servers
* Web browsers
* Security agents
* Monitoring systems
* Cloud applications
* Software update services

Exclude known DNS infrastructure and establish normal host-specific baselines.

---

## 7. Response

If abnormal activity is confirmed:

1. Identify the source endpoint.
2. Determine the process generating queries.
3. Review queried domains.
4. Search for related network activity.
5. Check for malware or C2 indicators.
6. Isolate the endpoint if compromise is suspected.

**Detection Goal:** Identify abnormal DNS query volume that may indicate automated or malicious activity.
