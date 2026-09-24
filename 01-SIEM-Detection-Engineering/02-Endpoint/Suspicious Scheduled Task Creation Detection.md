# Suspicious Scheduled Task Creation Detection

## 1. Detection Summary

**Use Case:** Suspicious Scheduled Task Creation

**Platform:** Microsoft Sentinel

**Data Source:** Windows Security Events

**Severity:** High

**MITRE ATT&CK:** T1053.005 – Scheduled Task/Job: Scheduled Task

### Description

Detects scheduled task creation involving suspicious command interpreters or script execution.

---

## 2. Detection Logic

```text
Scheduled Task Created
        ↓
Suspicious Command
        ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4698
| where TaskContent has_any (
    "powershell",
    "cmd.exe",
    "wscript",
    "mshta"
)
| project
    TimeGenerated,
    Computer,
    Account,
    TaskName,
    TaskContent
| order by TimeGenerated desc
```

### How it works

`4698` = **A scheduled task was created**.

The query then checks whether the task contains suspicious execution such as:

```text
Scheduled Task
     ↓
PowerShell / CMD / MSHTA
     ↓
Potential Persistence
```

---

## 4. Investigation

Review:

* Task name
* Creating user
* Task action
* Command/script
* Task location
* Execution schedule
* Parent process
* Related endpoint activity

---

## 5. False Positives & Tuning

Possible legitimate activity:

* Software updates
* IT administration
* Monitoring tools
* Enterprise management software

Tune using known task names, approved administrators, and trusted software.

---

## 6. Response

If malicious activity is confirmed:

1. Investigate the task.
2. Identify the creating user and process.
3. Review the command/script.
4. Remove the malicious task when appropriate.
5. Search for the same task across endpoints.
6. Investigate additional persistence mechanisms.

**Detection Status:** Ready for testing and tuning.
