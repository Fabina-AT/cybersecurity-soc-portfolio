# Newly Registered / Rare Domain Detection

## 1. Detection Summary

**Use Case:** Newly Registered / Rare Domain
**Platform:** Microsoft Sentinel
**Data Source:** DNS Logs + Threat Intelligence
**Severity:** Medium
**MITRE ATT&CK:** T1071.004 – DNS

### Description

Detects DNS queries to domains that are rarely observed or newly seen in the environment.

Attackers may use newly registered or low-prevalence domains for phishing, malware delivery, or command-and-control.

---

## 2. Detection Logic

```text
DNS Query
    ↓
Rare / Newly Seen Domain
    ↓
Threat Intelligence Check
    ↓
Endpoint Correlation
    ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
DnsEvents
| where TimeGenerated >= ago(24h)
| summarize
    QueryCount = count(),
    FirstSeen = min(TimeGenerated),
    Clients = dcount(ClientIP)
    by Name
| where QueryCount <= 3
| where FirstSeen >= ago(24h)
| project
    Name,
    QueryCount,
    Clients,
    FirstSeen
| order by FirstSeen desc
```

---

## 4. How It Works

The detection identifies domains that:

* Were first observed recently
* Have very few DNS queries
* May represent previously unseen infrastructure

Rare does not automatically mean malicious. Correlate with domain reputation and endpoint activity.

---

## 5. Investigation

Review:

* Domain reputation
* Domain registration information
* Source endpoint
* User
* Query frequency
* Related URLs
* Process generating the request
* Network connections
* Threat-intelligence matches

---

## 6. False Positives

Possible legitimate activity:

* New SaaS applications
* Newly deployed websites
* Software updates
* Cloud services
* Business partner domains

Maintain known trusted domains and baseline normal business traffic.

---

## 7. Response

If malicious activity is confirmed:

1. Identify affected endpoints.
2. Validate the domain using threat intelligence.
3. Identify the process generating the query.
4. Search for the domain across the environment.
5. Block the domain if confirmed malicious.
6. Investigate related phishing, malware, or C2 activity.

**Detection Goal:** Identify previously unseen DNS infrastructure that may be associated with malicious activity.
