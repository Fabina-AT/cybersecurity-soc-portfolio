# Suspicious Command-and-Control Communication Detection

## 1. Detection Summary

**Use Case:** Suspicious Command-and-Control (C2) Communication

**Platform:** Microsoft Sentinel

**Data Source:** Network / Firewall Logs

**Severity:** High

**MITRE ATT&CK:** T1071 – Application Layer Protocol

### Description

Detects repeated outbound connections from an internal host to the same external destination within a short period.

This behavior may indicate automated C2 beaconing.

---

## 2. Detection Logic

```text id="y3t6e1"
Internal Host
     ↓
Repeated Outbound Connections
     ↓
Same External IP
     ↓
Short Time Interval
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="m4m9qs"
CommonSecurityLog
| where TimeGenerated >= ago(15m)
| where DeviceAction = "Allow"
| where isnotempty(DestinationIP)
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

### How it works

The query identifies an internal host making **20+ outbound connections** to the same destination within 15 minutes.

Example:

```text id="o3q5m8"
Workstation
    ↓
10.20.10.15
    ↓
Repeated connections
    ↓
External IP
    ↓
Potential C2 Beaconing
```

> High connection frequency alone does not confirm C2. Investigate the destination, timing pattern, application, and endpoint process.

---

## 4. Investigation

Review:

* Source host
* Destination IP/domain
* Destination port
* Connection frequency
* Firewall action
* Application/process
* DNS history
* Threat-intelligence reputation
* Related endpoint alerts

---

## 5. False Positives & Tuning

Possible legitimate activity:

* Software updates
* Browsers
* Cloud applications
* Monitoring agents
* Security products

Tune using trusted destinations, approved applications, and connection-frequency baselines.

---

## 6. Response

If malicious C2 is suspected:

1. Investigate the destination.
2. Identify the process generating the traffic.
3. Check DNS and endpoint activity.
4. Block the destination when appropriate.
5. Isolate the endpoint if compromise is suspected.
6. Search for the same IOC across the environment.

**Detection Status:** Ready for testing and tuning.

