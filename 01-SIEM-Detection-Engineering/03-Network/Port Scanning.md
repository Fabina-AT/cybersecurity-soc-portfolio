# Port Scanning Detection

## 1. Detection Summary

**Use Case:** Network Port Scanning

**Platform:** Microsoft Sentinel

**Data Source:** Firewall / Network Logs

**Severity:** Medium

**MITRE ATT&CK:** T1046 – Network Service Scanning

### Description

Detects an internal or external source attempting connections to a large number of destination ports within a short period.

---

## 2. Detection Logic

```text
Network Connections
       ↓
Same Source IP
       ↓
Many Destination Ports
       ↓
Short Time Window
       ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
CommonSecurityLog
| where TimeGenerated >= ago(10m)
| summarize
    Ports = dcount(DestinationPort),
    Destinations = dcount(DestinationIP)
    by SourceIP
| where Ports >= 20 or Destinations >= 20
| project SourceIP, Ports, Destinations
| order by Ports desc
```

### How it works

The query identifies a source communicating with **many ports or many destinations within 10 minutes**.

Example:

```text
10.10.10.25
     ↓
22
80
443
445
3389
5985
...
     ↓
Potential Network Scan
```

---

## 4. Investigation

Review:

* Source IP
* Destination IPs
* Destination ports
* Internal/external source
* Firewall action
* Connection count
* Source host
* Related authentication activity
* Endpoint alerts

---

## 5. False Positives & Tuning

Possible legitimate activity:

* Vulnerability scanners
* Network monitoring
* IT administration
* Security assessment tools

Tune using approved scanner IPs and known security infrastructure.

---

## 6. Response

If unauthorized scanning is confirmed:

1. Identify the source host.
2. Determine the owner/user.
3. Review the destination systems.
4. Check for successful connections.
5. Investigate subsequent authentication or endpoint activity.
6. Block or isolate the source when appropriate.

**Detection Status:** Ready for testing and tuning.
