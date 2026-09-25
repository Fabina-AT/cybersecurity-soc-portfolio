# DNS NXDOMAIN Spike Detection

## 1. Detection Summary

**Use Case:** DNS NXDOMAIN Spike  
**Platform:** Microsoft Sentinel  
**Data Source:** DNS Logs  
**Severity:** Medium  
**MITRE ATT&CK:** T1071.004 – DNS

### Description

Detects an unusually high number of failed DNS lookups (`NXDOMAIN`) from an endpoint.

A spike in NXDOMAIN responses can indicate malware using DGA-generated domains, DNS reconnaissance, or abnormal application behavior.

---

## 2. Detection Logic

```text
DNS Queries
    ↓
NXDOMAIN Responses
    ↓
High Failure Volume
    ↓
Identify Source
    ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="j6y1kc"
DnsEvents
| where TimeGenerated >= ago(15m)
| where ResponseCode == "NXDOMAIN"
| summarize
    NXDomainCount = count(),
    Domains = dcount(Name)
    by ClientIP
| where NXDomainCount >= 50
| project
    ClientIP,
    NXDomainCount,
    Domains
| order by NXDomainCount desc
```

---

## 4. How It Works

The detection:

1. Reviews DNS activity from the last 15 minutes.
2. Filters for `NXDOMAIN` responses.
3. Counts failed DNS lookups per client.
4. Alerts when a client generates **50 or more NXDOMAIN responses**.

A high NXDOMAIN count alone does not confirm malicious activity.

---

## 5. Investigation

Review:

- Client IP
- Number of failed queries
- Unique domains
- Queried domain names
- Query timestamps
- Process generating DNS requests
- Endpoint security alerts
- Related network connections

Look for multiple random-looking or similar domains from the same endpoint.

---

## 6. False Positives

Possible legitimate causes:

- Browser activity
- Misconfigured applications
- Software updates
- Security tools
- DNS configuration issues

Establish normal DNS baselines before tuning the threshold.

---

## 7. Response

If malicious activity is suspected:

1. Identify the affected endpoint.
2. Review the failed DNS domains.
3. Identify the process generating the queries.
4. Search the domains across the environment.
5. Check for DGA or C2 indicators.
6. Investigate related endpoint activity.
7. Isolate the endpoint if compromise is confirmed.

**Detection Goal:** Identify abnormal DNS failure patterns that may indicate DGA activity, reconnaissance, or malware-related DNS communication.
