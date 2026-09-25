# Network Service Discovery Detection

## 1. Detection Summary

**Use Case:** Network Service Discovery
**Platform:** Microsoft Sentinel
**Data Source:** Network / Firewall Logs
**Severity:** Medium
**MITRE ATT&CK:** T1046 – Network Service Scanning

### Description

Detects internal hosts connecting to multiple destination ports across internal systems.

This activity may indicate an attacker identifying available network services before attempting exploitation or lateral movement.

---

## 2. Detection Logic

```text
Internal Host
     ↓
Connects to Multiple Services
     ↓
Different Ports / Hosts
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
| where ipv4_is_private(DestinationIP)
| summarize
    Services = dcount(DestinationPort),
    Hosts = dcount(DestinationIP)
    by SourceIP
| where Services >= 10 and Hosts >= 5
| project
    SourceIP,
    Services,
    Hosts
| order by Services desc
```

---

## 4. How It Works

The detection identifies an internal source connecting to:

* Multiple destination hosts
* Multiple network services

within a short period.

Example:

```text
PC01
 ↓
Server01:445
Server02:445
Server03:3389
Server04:22
Server05:80
...
```

This can indicate an attempt to identify accessible services in the internal environment.

---

## 5. Investigation

Review:

* Source host
* Source user
* Destination hosts
* Destination ports
* Connection frequency
* Process generating the traffic
* Previous authentication activity
* Subsequent lateral movement

Pay particular attention to ports such as **445, 3389, 5985, 5986, 22, and 80/443**.

---

## 6. False Positives

Possible legitimate activity:

* Vulnerability scanners
* Network monitoring
* IT administration
* Asset discovery
* Configuration management tools

Baseline approved discovery systems.

---

## 7. Response

If unauthorized discovery is suspected:

1. Identify the source endpoint and user.
2. Determine the process generating the connections.
3. Review discovered hosts and services.
4. Search for subsequent authentication or exploitation.
5. Investigate related endpoint activity.
6. Isolate the endpoint if compromise is suspected.

**Detection Goal:** Identify suspicious internal service discovery that may precede exploitation or lateral movement.
