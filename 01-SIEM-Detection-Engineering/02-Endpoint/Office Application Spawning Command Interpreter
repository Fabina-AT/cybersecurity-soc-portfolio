# Office Application Spawning Command Interpreter Detection

## 1. Detection Summary

**Use Case:** Office Application Spawning Command Interpreter

**Platform:** Microsoft Sentinel

**Data Source:** Windows Security Events (`4688`)

**Severity:** High

**MITRE ATT&CK:** T1204.002 – Malicious File

### Description

Detects cases where Microsoft Office applications such as Word or Excel start command interpreters such as `cmd.exe`, PowerShell, or scripting engines.

This behavior can indicate malicious documents or macro-based execution.

---

## 2. Detection Logic

```text
Office Application
       ↓
Starts Command Interpreter
       ↓
Review Command Line
       ↓
Generate Alert
       ↓
SOC Investigation
```

Examples:

```text
WINWORD.EXE → cmd.exe
EXCEL.EXE   → powershell.exe
OUTLOOK.EXE → powershell.exe
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| where ParentProcessName has_any (
    "winword.exe",
    "excel.exe",
    "outlook.exe",
    "powerpnt.exe"
)
| where NewProcessName has_any (
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
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

---

## 4. How It Works

For example:

```text
WINWORD.EXE
     ↓
powershell.exe
     ↓
Command Execution
```

The query checks:

1. Was an Office application the parent?
2. Did it start a command/script interpreter?
3. What user and computer were involved?
4. What command was executed?

If these conditions match, the event is returned for investigation.

---

## 5. Investigation

Review:

* User
* Host
* Parent process
* Child process
* Command line
* Document name/path
* Network connections
* File creation
* Related PowerShell activity
* Other alerts on the endpoint

Pay particular attention when the process chain is:

```text
Email Attachment
      ↓
Microsoft Word
      ↓
PowerShell / CMD
      ↓
Network Connection
      ↓
File Download
```

---

## 6. False Positives & Tuning

Possible legitimate activity:

* Administrative scripts
* Office automation
* Enterprise macros
* Software management tools

Tune using:

* Approved applications
* Known scripts
* Administrative systems
* Trusted automation accounts

Avoid excluding Office applications globally.

---

## 7. Response

If malicious execution is confirmed:

1. Identify the originating document.
2. Review the process tree.
3. Analyze the command line.
4. Investigate network connections.
5. Search for the same process chain on other endpoints.
6. Isolate the endpoint when appropriate.
7. Preserve relevant evidence.
8. Escalate according to the incident-response process.

---

## 8. Validation

Use an approved test environment to generate controlled process activity.

Verify that the detection captures:

* Parent process
* Child process
* User
* Host
* Command line

**Detection Status:** Ready for testing and tuning.
