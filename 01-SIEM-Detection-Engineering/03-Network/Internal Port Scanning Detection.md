# Internal Port Scanning Detection

## 1. Detection Summary

**Use Case:** Internal Port Scanning
**Platform:** Microsoft Sentinel
**Data Source:** Network / Firewall Logs
**Severity:** Medium
**MITRE ATT&CK:** T1046 – Network Service Scanning

### Description

Detects an internal host connecting to multiple destination ports or hosts within a short period.

This behavior may indicate reconnaissance before lateral movement.

---

## 2. Detection Logic

```text
Internal Source
      ↓
Multiple Connections
      ↓
Many Ports / Hosts
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
| where ipv4_is_private(SourceIP)
| summarize
    Ports = dcount(DestinationPort),
    Hosts = dcount(DestinationIP)
    by SourceIP
| where Ports >= 20 or Hosts >= 20
| project
    SourceIP,
    Ports,
    Hosts
| order by Hosts desc
```

---

## 4. How It Works

The detection identifies an internal source that communicates with:

* Many different ports, or
* Many different destination hosts

within **10 minutes**.

Example:

```text
PC01
 ↓
Server01:22
Server02:22
Server03:22
Server04:80
Server05:445
Server06:3389
...
```

This may indicate an attacker looking for available services.

---

## 5. Investigation

Review:

* Source host
* Source user
* Destination hosts
* Destination ports
* Connection timestamps
* Allowed/blocked actions
* Endpoint process activity
* Vulnerability scanner activity

Determine whether the source is an approved scanner or an ordinary workstation.

---

## 6. False Positives

Possible legitimate activity:

* Vulnerability scanners
* Network monitoring
* IT administration
* Asset discovery tools
* Security assessment tools

Exclude approved scanning infrastructure where appropriate.

---

## 7. Response

If unauthorized scanning is identified:

1. Identify the source endpoint.
2. Determine the associated user/process.
3. Review destinations and discovered services.
4. Search for subsequent authentication or lateral movement.
5. Isolate the endpoint if compromise is suspected.
6. Investigate related security alerts.

**Detection Goal:** Identify internal reconnaissance that may precede lateral movement or exploitation.
