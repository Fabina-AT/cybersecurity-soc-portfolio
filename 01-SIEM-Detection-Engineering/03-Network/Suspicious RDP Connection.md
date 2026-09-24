# Suspicious RDP Connection Detection

## 1. Detection Summary

**Use Case:** Suspicious RDP Connection

**Platform:** Microsoft Sentinel

**Data Source:** Network / Firewall Logs

**Severity:** High

**MITRE ATT&CK:** T1021.001 – Remote Services: RDP

### Description

Detects successful inbound RDP connections from external or unusual source IP addresses to internal systems.

This can help identify exposed RDP services and potential unauthorized remote access.

---

## 2. Detection Logic

```text
Inbound RDP
     ↓
External Source
     ↓
Connection Allowed
     ↓
Destination Port 3389
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where DeviceAction =~ "Allow"
| where DestinationPort == 3389
| summarize
    Connections = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP
| project
    SourceIP,
    DestinationIP,
    Connections,
    FirstSeen,
    LastSeen
| order by Connections desc
```

---

## 4. Investigation

Review:

* Source IP reputation
* Destination host
* Connection frequency
* User authentication events
* RDP logon events
* Geographic location
* Whether the source IP is approved

Correlate with Windows logon events such as **4624** and **4625**.

---

## 5. False Positives

Possible legitimate activity:

* Authorized remote administration
* IT support
* Approved external support vendors
* Corporate VPN infrastructure

Maintain approved source IPs where appropriate.

---

## 6. Response

If unauthorized activity is confirmed:

1. Block the source IP.
2. Investigate the destination host.
3. Review successful and failed logons.
4. Check for privilege escalation or lateral movement.
5. Search for additional activity from the source IP.
6. Isolate the endpoint if compromise is suspected.

---

## 7. Validation

Test using an authorized lab environment and verify that the detection captures:

* Source IP
* Destination IP
* Port 3389
* Connection timestamp
* Connection count
* Allowed/blocked action

**Detection Goal:** Identify externally accessible or suspicious RDP activity before it leads to unauthorized remote access.
