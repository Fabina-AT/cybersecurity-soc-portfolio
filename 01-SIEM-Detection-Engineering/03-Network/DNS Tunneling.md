# DNS Tunneling Detection

## 1. Detection Summary

**Use Case:** DNS Tunneling
**Platform:** Microsoft Sentinel
**Data Source:** DNS Logs
**Severity:** High
**MITRE ATT&CK:** T1071.004 – DNS

### Description

Detects unusually high DNS query activity and long query names from an internal host.

Attackers may abuse DNS to establish covert communication or transfer data through DNS queries.

---

## 2. Detection Logic

```text
Internal Host
     ↓
High DNS Query Volume
     ↓
Long / Unusual Query Names
     ↓
Same Domain
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
DnsEvents
| where TimeGenerated >= ago(15m)
| extend QueryLength = strlen(Name)
| summarize
    Queries = count(),
    AvgQueryLength = avg(QueryLength),
    MaxQueryLength = max(QueryLength)
    by ClientIP, Domain = tostring(split(Name, ".")[-2])
| where Queries >= 100 and AvgQueryLength >= 40
| project
    ClientIP,
    Domain,
    Queries,
    AvgQueryLength,
    MaxQueryLength
| order by Queries desc
```

---

## 4. How It Works

The detection looks for:

* High DNS query volume
* Long DNS query names
* Repeated queries to the same domain

A combination of **high volume + unusually long queries** can indicate possible DNS tunneling.

---

## 5. Investigation

Review:

* Source host
* Queried domain
* Query frequency
* Query length
* DNS record type
* Domain reputation
* Process generating DNS requests
* Other network connections from the host

Look for encoded or randomly generated subdomains.

Example:

```text
aj39dk29xk29dk.example.com
8fj39dk20sl29.example.com
k29dk29s8fj20.example.com
```

---

## 6. False Positives

Possible legitimate activity:

* Security software
* CDN services
* Cloud applications
* Telemetry systems
* Applications using long dynamic DNS names

Tune known trusted domains and normal DNS baselines.

---

## 7. Response

If DNS tunneling is suspected:

1. Identify the affected endpoint.
2. Investigate the queried domain.
3. Identify the process generating the queries.
4. Search for the domain across the environment.
5. Block confirmed malicious domains.
6. Investigate possible C2 or data-exfiltration activity.

**Detection Goal:** Identify abnormal DNS behavior that may indicate covert C2 communication or data tunneling.
