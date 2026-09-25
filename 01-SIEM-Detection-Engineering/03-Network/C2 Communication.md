# C2 Communication Detection

## 1. Detection Summary

**Use Case:** Command-and-Control (C2) Communication
**Platform:** Microsoft Sentinel
**Data Source:** Network / Firewall Logs
**Severity:** High
**MITRE ATT&CK:** T1071 – Application Layer Protocol

### Description

Detects repeated outbound connections from an internal host to the same external destination within a short time period.

This behavior may indicate automated command-and-control communication.

---

## 2. Detection Logic

```text
Internal Host
     ↓
Repeated Outbound Connections
     ↓
Same External Destination
     ↓
High Connection Frequency
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
CommonSecurityLog
| where TimeGenerated >= ago(15m)
| where DeviceAction =~ "Allow"
| where ipv4_is_private(SourceIP)
| where ipv4_is_private(DestinationIP) == false
| summarize
    Connections = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP, DestinationPort
| where Connections >= 20
| project
    SourceIP,
    DestinationIP,
    DestinationPort,
    Connections,
    FirstSeen,
    LastSeen
| order by Connections desc
```

---

## 4. How It Works

The detection:

1. Looks at allowed outbound traffic.
2. Identifies internal sources communicating with external IPs.
3. Groups connections by source, destination, and port.
4. Flags destinations receiving **20+ connections within 15 minutes**.

High connection frequency alone does **not** confirm C2. Endpoint and threat-intelligence correlation should be used during investigation.

---

## 5. Investigation

Review:

* Source endpoint
* Destination IP/domain
* Destination reputation
* Connection frequency and timing
* Destination port/protocol
* Process responsible for the traffic
* DNS activity
* Other alerts from the endpoint

---

## 6. False Positives

Possible legitimate activity:

* Software updates
* Security agents
* Monitoring systems
* Cloud applications
* Backup services

Tune known trusted destinations and expected high-frequency traffic.

---

## 7. Response

If malicious C2 activity is confirmed:

1. Identify the responsible process.
2. Investigate the destination infrastructure.
3. Search for the destination across the environment.
4. Block confirmed malicious infrastructure.
5. Isolate the affected endpoint if required.
6. Investigate persistence and additional attacker activity.

**Detection Goal:** Identify suspicious outbound communication that may represent command-and-control activity.


