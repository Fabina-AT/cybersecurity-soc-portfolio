# Suspicious DNS Resolution Detection

## 1. Detection Summary

**Use Case:** Suspicious DNS Resolution  
**Platform:** Microsoft Sentinel  
**Data Source:** DNS Logs  
**Severity:** High  
**MITRE ATT&CK:** T1071.004 – DNS

### Description

Detects DNS queries that resolve to suspicious or potentially malicious IP addresses.

This can help identify endpoints communicating with known malicious infrastructure.

---

## 2. Detection Logic

```text
DNS Query
    ↓
Domain Resolution
    ↓
Check Resolved IP
    ↓
Threat Intelligence Match
    ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="6xq7pa"
DnsEvents
| where TimeGenerated >= ago(24h)
| where ipv4_is_private(IPAddresses) == false
| join kind=inner (
    ThreatIntelligenceIndicator
    | where Active == true
    | where IndicatorType == "ipv4"
    | project ThreatIP = NetworkIP, ThreatType = ThreatDescription
) on $left.IPAddresses == $right.ThreatIP
| project
    TimeGenerated,
    ClientIP,
    Name,
    IPAddresses,
    ThreatType
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection:

1. Reviews DNS resolution activity.
2. Identifies public IP addresses returned by DNS.
3. Correlates resolved IPs with active threat-intelligence indicators.
4. Generates an alert when a DNS resolution matches known threat infrastructure.

---

## 5. Investigation

Review:

- Client IP
- Queried domain
- Resolved IP
- Threat-intelligence description
- Query timestamp
- User
- Process generating the request
- Related network connections
- Endpoint security alerts

---

## 6. False Positives

Possible causes include:

- Shared hosting
- Cloud infrastructure
- CDN services
- Threat-intelligence inaccuracies
- Reused IP addresses

Validate the indicator before taking blocking actions.

---

## 7. Response

If malicious activity is confirmed:

1. Identify the affected endpoint.
2. Validate the threat-intelligence indicator.
3. Investigate the queried domain.
4. Identify the process responsible.
5. Search for the IP/domain across the environment.
6. Block confirmed malicious infrastructure.
7. Investigate the endpoint for compromise.

**Detection Goal:** Identify DNS resolutions associated with known malicious infrastructure.
