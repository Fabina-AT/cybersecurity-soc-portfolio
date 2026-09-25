# DGA / Randomized Domain Detection

## 1. Detection Summary

**Use Case:** DGA / Randomized Domain Detection  
**Platform:** Microsoft Sentinel  
**Data Source:** DNS Logs  
**Severity:** High  
**MITRE ATT&CK:** T1071.004 – DNS

### Description

Detects repeated DNS queries to unusually long domain names that may indicate Domain Generation Algorithm (DGA) activity or malware-related DNS communication.

---

## 2. Detection Logic

```text
DNS Query
    ↓
Extract Domain
    ↓
Long Domain Name
    ↓
Repeated Queries
    ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
DnsEvents
| where TimeGenerated >= ago(15m)
| extend Domain = tostring(split(Name, ".")[-2])
| summarize
    Queries = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ClientIP, Domain
| where Queries >= 5 and strlen(Domain) >= 15
| project
    FirstSeen,
    LastSeen,
    ClientIP,
    Domain,
    Queries
| order by Queries desc
```

---

## 4. How It Works

The detection:

1. Reviews DNS queries from the last 15 minutes.
2. Extracts the second-level domain using `[-2]`.
3. Counts repeated queries from each client.
4. Flags domains with:
   - At least **5 queries**
   - Domain length of **15 or more characters**

Long or repeated domains do not automatically indicate DGA. Threat intelligence and endpoint activity should be used for validation.

---

## 5. Investigation

Review:

- Client IP
- Queried domain
- Query frequency
- First and last activity
- Domain reputation
- Domain registration information
- DNS response
- Process generating the DNS request
- Related network connections
- Endpoint security alerts

Look for multiple unusual domains queried by the same endpoint.

---

## 6. False Positives

Possible legitimate activity:

- CDN services
- Cloud applications
- Tracking systems
- Security software
- Application-generated domains

Tune known trusted domains and establish normal DNS baselines.

---

## 7. Response

If malicious DGA activity is confirmed:

1. Identify the affected endpoint.
2. Investigate the queried domain.
3. Identify the process generating DNS requests.
4. Search the domain across the environment.
5. Check for related C2 indicators.
6. Block confirmed malicious domains.
7. Isolate the endpoint if compromise is confirmed.

**Detection Goal:** Identify abnormal DNS patterns that may indicate malware-generated or suspicious C2 infrastructure.
