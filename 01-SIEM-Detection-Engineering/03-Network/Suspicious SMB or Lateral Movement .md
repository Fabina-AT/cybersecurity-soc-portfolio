# Suspicious SMB / Lateral Movement Detection

## 1. Detection Summary

**Use Case:** Suspicious SMB / Lateral Movement
**Platform:** Microsoft Sentinel
**Data Source:** Network / Firewall Logs
**Severity:** High
**MITRE ATT&CK:** T1021.002 – SMB/Windows Admin Shares

### Description

Detects internal hosts making SMB connections to multiple systems within a short period.

This behavior may indicate lateral movement using SMB or Windows administrative shares.

---

## 2. Detection Logic

```text
Internal Host
     ↓
SMB Connections
     ↓
Multiple Destination Hosts
     ↓
Short Time Window
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
CommonSecurityLog
| where TimeGenerated >= ago(15m)
| where DeviceAction =~ "Allow"
| where DestinationPort in (445, 139)
| summarize
    Destinations = dcount(DestinationIP),
    Connections = count(),
    TargetHosts = make_set(DestinationIP, 20)
    by SourceIP
| where Destinations >= 10
| project
    SourceIP,
    Destinations,
    Connections,
    TargetHosts
| order by Destinations desc
```

---

## 4. Investigation

Review:

* Source host
* Destination hosts
* User associated with the source
* SMB authentication events
* Access to administrative shares
* Process activity on the source endpoint
* Other lateral movement alerts

Correlate with Windows events such as **4624**, **4648**, and **5140** where available.

---

## 5. False Positives

Possible legitimate activity:

* File servers
* Backup systems
* Software deployment
* IT administration
* Vulnerability scanners

Baseline known administrative systems and expected SMB traffic.

---

## 6. Response

If unauthorized lateral movement is suspected:

1. Identify the source endpoint.
2. Review the process responsible for the connections.
3. Investigate destination systems.
4. Check for privileged authentication.
5. Isolate compromised endpoints if required.
6. Search for additional lateral movement activity.

**Detection Goal:** Identify unusual SMB activity that may indicate internal lateral movement.
