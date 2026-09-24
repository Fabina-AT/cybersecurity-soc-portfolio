# Suspicious WMI Execution Detection

## 1. Detection Summary

**Use Case:** Suspicious WMI Execution

**Platform:** Microsoft Sentinel

**Data Source:** Windows Security Events (`4688`)

**Severity:** High

**MITRE ATT&CK:** T1047 – Windows Management Instrumentation

### Description

Detects suspicious use of Windows Management Instrumentation (WMI) to execute commands or scripts.

---

## 2. Detection Logic

```text
WMI Process
    ↓
Command / Script Execution
    ↓
Review User + Host
    ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| where ParentProcessName has_any (
    "wmiprvse.exe",
    "wmic.exe"
)
| where NewProcessName has_any (
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe"
)
| project
    TimeGenerated,
    Computer,
    Account,
    ParentProcessName,
    NewProcessName,
    CommandLine
| order by TimeGenerated desc
```

### How it works

The query looks for command or script interpreters being launched through WMI.

```text
WMI
 ↓
wmiprvse.exe
 ↓
cmd.exe / powershell.exe
 ↓
Command Execution
```

This can be legitimate administration or potentially malicious execution, so the process context must be investigated.

---

## 4. Investigation

Review:

* User
* Source and destination host
* Parent process
* Child process
* Command line
* Remote activity
* Network connections
* Related authentication events
* Other endpoint alerts

---

## 5. False Positives & Tuning

Possible legitimate activity:

* IT administration
* SCCM/endpoint management
* Monitoring tools
* System automation

Tune using known management servers, service accounts, and approved administrative activity.

---

## 6. Response

If malicious activity is confirmed:

1. Identify the source and target hosts.
2. Review the WMI command.
3. Investigate the user account.
4. Search for related process activity.
5. Investigate lateral movement.
6. Isolate affected endpoints when appropriate.
7. Escalate according to the incident-response process.

**Detection Status:** Ready for testing and tuning.
