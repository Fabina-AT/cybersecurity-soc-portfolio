# Unusual Outbound Traffic / Data Exfiltration Detection

## 1. Detection Summary

**Use Case:** Unusual Outbound Traffic / Data Exfiltration
**Platform:** Microsoft Sentinel
**Data Source:** Network / Firewall Logs
**Severity:** High
**MITRE ATT&CK:** T1041 – Exfiltration Over C2 Channel

### Description

Detects unusually large amounts of data transferred from an internal host to an external destination within a short period.

This may indicate data exfiltration from a compromised system.

---

## 2. Detection Logic

```text
Internal Host
     ↓
Large Outbound Data Transfer
     ↓
External Destination
     ↓
Threshold Exceeded
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where DeviceAction =~ "Allow"
| where ipv4_is_private(SourceIP)
| where ipv4_is_private(DestinationIP) == false
| summarize
    OutboundBytes = sum(SentBytes),
    Connections = count()
    by SourceIP, DestinationIP
| where OutboundBytes >= 500000000
| project
    SourceIP,
    DestinationIP,
    OutboundBytes,
    Connections
| order by OutboundBytes desc
```

---

## 4. How It Works

The detection:

1. Looks at allowed outbound traffic.
2. Identifies internal-to-external connections.
3. Calculates the total bytes sent.
4. Alerts when outbound traffic exceeds **500 MB within 1 hour**.

Example:

```text
PC01
  ↓
External IP
  ↓
650 MB sent / 1 hour
  ↓
Alert
```

High data volume alone does **not** confirm exfiltration. The destination, user, application, and normal traffic baseline should be reviewed.

---

## 5. Investigation

Review:

* Source endpoint
* Destination IP/domain
* Amount of data transferred
* User
* Application/process
* Destination reputation
* File activity
* Cloud storage activity
* Previous communication with the destination

Correlate with endpoint and DLP events where available.

---

## 6. False Positives

Possible legitimate activity:

* Cloud backups
* Software distribution
* Large file transfers
* Video/media systems
* Cloud synchronization
* Database replication

Baseline known high-volume systems and destinations.

---

## 7. Response

If unauthorized data transfer is suspected:

1. Identify the source endpoint.
2. Determine what data was transferred.
3. Investigate the destination.
4. Search for the same destination across the environment.
5. Block confirmed malicious destinations.
6. Isolate the endpoint if compromise is suspected.
7. Escalate for data-loss investigation.

**Detection Goal:** Identify abnormal outbound data transfers that may indicate data exfiltration.
