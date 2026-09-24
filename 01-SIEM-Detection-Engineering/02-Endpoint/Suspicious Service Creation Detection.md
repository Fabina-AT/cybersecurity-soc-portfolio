# Suspicious Service Creation Detection

## 1. Detection Summary

**Use Case:** Suspicious Service Creation

**Platform:** Microsoft Sentinel

**Data Source:** Windows Security Events

**Severity:** High

**MITRE ATT&CK:** T1543.003 – Create or Modify System Process: Windows Service

### Description

Detects creation of new Windows services that may be used for persistence or malicious execution.

---

## 2. Detection Logic

```text
New Service Created
       ↓
Review Service Command
       ↓
Suspicious Path / Command
       ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 7045
| where ServiceFileName has_any (
    "powershell",
    "cmd.exe",
    "wscript",
    "mshta"
)
| project
    TimeGenerated,
    Computer,
    Account,
    ServiceName,
    ServiceFileName
| order by TimeGenerated desc
```

### How it works

`7045` indicates that a **new service was installed**.

The query then checks whether the service executes suspicious interpreters:

```text
New Service
    ↓
PowerShell / CMD / MSHTA
    ↓
Potential Persistence
    ↓
Alert
```

---

## 4. Investigation

Review:

* Service name
* Service executable/path
* Creating account
* Command line
* Service start type
* Process creation
* Related authentication activity
* Other alerts on the host

---

## 5. False Positives & Tuning

Possible legitimate activity:

* Software installation
* Windows updates
* Endpoint management tools
* Security software

Tune using approved software and known service names.

---

## 6. Response

If malicious activity is confirmed:

1. Investigate the service.
2. Identify the executable.
3. Review the creating account.
4. Disable/remove the malicious service when appropriate.
5. Search for the same service across endpoints.
6. Investigate additional persistence mechanisms.

**Detection Status:** Ready for testing and tuning.
