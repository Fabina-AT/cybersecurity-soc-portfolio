# Ransomware Mass File Modification Detection

## 1. Detection Summary

**Use Case:** Ransomware / Mass File Modification

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Defender for Endpoint (`DeviceFileEvents`)

**Severity:** Critical

**MITRE ATT&CK:** T1486 – Data Encrypted for Impact

### Description

Detects an unusually high number of file modifications from the same process on an endpoint, which may indicate ransomware activity.

---

## 2. Detection Logic

```text
Many File Changes
       ↓
Same Device + Process
       ↓
100+ Changes / 10 Minutes
       ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
DeviceFileEvents
| where Timestamp >= ago(10m)
| summarize FileChanges = count()
    by DeviceName, InitiatingProcessFileName
| where FileChanges >= 100
| project DeviceName, InitiatingProcessFileName, FileChanges
| order by FileChanges desc
```

### How it works

```text
Device A
   ↓
unknown.exe
   ↓
250 file changes
   ↓
Alert
```

The query identifies a process making **100 or more file changes within 10 minutes** on the same device.

---

## 4. Investigation

Review:

* Device
* User
* Process
* File extensions
* File paths
* Process command line
* Network shares
* Related security alerts

---

## 5. False Positives & Tuning

Possible legitimate activity:

* Backup software
* File synchronization
* Software updates
* Data-processing applications

Tune the threshold and exclude known trusted processes where appropriate.

---

## 6. Response

If ransomware is suspected:

1. Investigate the process.
2. Isolate the endpoint when appropriate.
3. Check for other affected devices.
4. Investigate network shares.
5. Preserve evidence.
6. Escalate the incident.

**Detection Status:** Ready for testing and tuning.
