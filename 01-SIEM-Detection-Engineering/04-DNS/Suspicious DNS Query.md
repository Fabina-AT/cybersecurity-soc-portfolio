# Suspicious DNS Query Detection

## 1. Detection Summary

**Use Case:** Suspicious DNS Query
**Platform:** Microsoft Sentinel
**Data Source:** DNS Logs
**Severity:** Medium
**MITRE ATT&CK:** T1071.004 – DNS

### Description

Detects DNS queries containing suspicious or commonly abused domains and patterns that may indicate malware communication, phishing, or attacker infrastructure.

---

## 2. Detection Logic

```text
DNS Query
    ↓
Suspicious Domain / Pattern
    ↓
Check Reputation
    ↓
Correlate Endpoint Activity
    ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
DnsEvents
| where TimeGenerated >= ago(24h)
| where Name has_any (
    ".tk",
    ".top",
    ".xyz",
    ".click",
    ".pw"
)
| summarize
    Queries = count(),
    Clients = dcount(ClientIP)
    by Name
| where Queries >= 3
| project Name, Queries, Clients
| order by Queries desc
```

---

## 4. How It Works

The detection:

1. Searches recent DNS queries.
2. Identifies domains using commonly abused TLDs.
3. Counts query frequency and affected clients.
4. Generates candidates for investigation.

The TLD alone does **not** confirm malicious activity.

---

## 5. Investigation

Review:

* Queried domain
* Source endpoint
* User
* Query frequency
* Domain age/reputation
* DNS record type
* Process generating the query
* Related network connections
* Endpoint alerts

---

## 6. False Positives

Possible legitimate activity includes:

* Newly deployed applications
* Marketing platforms
* Cloud services
* Development/test environments
* Legitimate domains using uncommon TLDs

Tune trusted domains and organizational baselines.

---

## 7. Response

If malicious activity is confirmed:

1. Identify the affected endpoint.
2. Investigate the domain reputation.
3. Identify the process generating DNS requests.
4. Search the domain across the environment.
5. Block confirmed malicious infrastructure.
6. Investigate related endpoint and network activity.

**Detection Goal:** Identify suspicious DNS activity that may indicate malicious infrastructure or compromised endpoints.
