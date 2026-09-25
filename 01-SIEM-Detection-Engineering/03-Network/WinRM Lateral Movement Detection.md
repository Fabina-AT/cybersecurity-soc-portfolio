# WinRM Lateral Movement Detection

## 1. Detection Summary

**Use Case:** Lateral Movement via WinRM
**Platform:** Microsoft Sentinel
**Data Source:** Windows Security Events / Network Logs
**Severity:** High
**MITRE ATT&CK:** T1021.006 – Windows Remote Management

### Description

Detects WinRM connections between internal systems that may indicate remote command execution or lateral movement.

WinRM commonly uses **TCP 5985 (HTTP)** and **5986 (HTTPS)**.

---

## 2. Detection Logic

```text id="1ezqf9"
Internal Source
      ↓
WinRM Connection
      ↓
Internal Destination
      ↓
Unusual Remote Access
      ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="jydy0c"
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where DeviceAction =~ "Allow"
| where DestinationPort in (5985, 5986)
| where ipv4_is_private(SourceIP)
| where ipv4_is_private(DestinationIP)
| summarize
    Connections = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP, DestinationPort
| where Connections >= 3
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

The detection identifies internal systems communicating over WinRM ports:

```text
PC01
  ↓ TCP 5985
Server01
```

Repeated or unexpected WinRM connections can indicate remote administration or potential lateral movement.

The network event should be correlated with Windows authentication and process activity before determining whether the activity is malicious.

---

## 5. Investigation

Review:

* Source host
* Destination host
* User account
* Destination port
* Authentication events
* PowerShell activity
* Process creation
* Remote execution activity
* Whether the source is an approved administration system

Correlate with Windows events such as **4624** and **4688** where available.

---

## 6. False Positives

Possible legitimate activity:

* PowerShell Remoting
* IT administration
* Configuration management
* Server management
* Automated deployment tools

Baseline authorized management systems.

---

## 7. Response

If unauthorized WinRM activity is identified:

1. Identify the source user and endpoint.
2. Review authentication activity.
3. Investigate PowerShell/process execution.
4. Check the destination system for additional activity.
5. Search for the same source across other hosts.
6. Isolate affected endpoints if compromise is suspected.

**Detection Goal:** Identify suspicious WinRM activity that may indicate internal lateral movement or remote command execution.
