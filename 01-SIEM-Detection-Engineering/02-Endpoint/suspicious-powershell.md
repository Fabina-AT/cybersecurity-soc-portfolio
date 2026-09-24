# Suspicious PowerShell Execution Detection

## 1. Detection Summary

**Use Case:** Suspicious PowerShell Execution

**Platform:** Microsoft Sentinel

**Data Source:** Windows Security Events (`4688`)

**Severity:** High

**MITRE ATT&CK:** T1059.001 – PowerShell

### Description

Detects potentially malicious PowerShell execution by correlating suspicious command-line behavior with the parent process and execution context.

---

## 2. Detection Logic

```text
PowerShell Execution
        ↓
Suspicious Parameters / Obfuscation
        ↓
Parent Process Analysis
        ↓
User + Host Context
        ↓
Generate Alert
        ↓
SOC Investigation
```

### High-Risk Indicators

* `-EncodedCommand`
* `-ExecutionPolicy Bypass`
* `-WindowStyle Hidden`
* `-NoProfile`
* `DownloadString`
* `Invoke-WebRequest`
* `IEX`
* PowerShell launched by Office or scripting applications

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| extend
    SuspiciousParameter = CommandLine has_any (
        "-EncodedCommand",
        "-ExecutionPolicy Bypass",
        "-WindowStyle Hidden",
        "-NoProfile"
    ),
    DownloadActivity = CommandLine has_any (
        "DownloadString",
        "DownloadFile",
        "Invoke-WebRequest",
        "IEX"
    ),
    SuspiciousParent = ParentProcessName has_any (
        "winword.exe",
        "excel.exe",
        "outlook.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    )
| where SuspiciousParameter
    or DownloadActivity
    or SuspiciousParent
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    CommandLine,
    ParentProcessName,
    SuspiciousParameter,
    DownloadActivity,
    SuspiciousParent
| order by TimeGenerated desc
```

---

## 4. Investigation

Prioritize alerts where multiple indicators are present.

Review:

* PowerShell command line
* Parent process
* User
* Host
* Encoded or obfuscated content
* Network connections
* Child processes
* File creation
* Related EDR/SIEM alerts
* Authentication activity

Example high-risk chain:

```text
Word
  ↓
PowerShell
  ↓
Encoded Command
  ↓
Network Connection
  ↓
File/Process Creation
```

---

## 5. False Positives & Tuning

Legitimate activity may include:

* Administrative automation
* Software deployment
* Configuration management
* Monitoring tools
* Approved PowerShell scripts

Tune using:

* Approved scripts
* Management servers
* Service accounts
* Administrative users
* Known parent processes

Avoid broad exclusions for PowerShell itself.

---

## 6. Response

If malicious execution is confirmed:

1. Analyze the PowerShell command.
2. Investigate the parent and child processes.
3. Review network connections and downloaded files.
4. Search for the same command across other hosts.
5. Isolate the endpoint when appropriate.
6. Preserve relevant evidence.
7. Escalate according to the incident-response process.

---

## 7. Validation

Test controlled PowerShell activity using approved test scenarios.

Validate that the detection identifies:

* Suspicious command-line indicators
* Parent process
* User
* Host
* Related execution context

**Detection Status:** Ready for testing and tuning.
