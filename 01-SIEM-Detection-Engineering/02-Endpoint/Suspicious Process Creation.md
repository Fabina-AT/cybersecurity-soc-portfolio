# Suspicious Process Creation Detection

## 1. Detection Summary

**Use Case:** Suspicious Process Creation

**Platform:** Microsoft Sentinel

**Data Source:** Windows Security Events (`4688`)

**Severity:** Medium

**MITRE ATT&CK:** T1059 – Command and Scripting Interpreter

### Description

Detects process creation involving command interpreters and scripting engines when they are launched from unusual or potentially suspicious parent processes.

This can help identify malicious execution chains on Windows endpoints.

---

## 2. Detection Logic

```text
Process Creation
      ↓
Suspicious Parent
      ↓
Command / Script Interpreter
      ↓
Review Process Chain
      ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| extend
    SuspiciousParent = ParentProcessName has_any (
        "winword.exe",
        "excel.exe",
        "outlook.exe",
        "powerpnt.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe"
    )
    ScriptInterpreter = NewProcessName has_any (
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    )
| where SuspiciousParent and ScriptInterpreter
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

The detection looks for a suspicious process relationship.

Example:

```text
EXCEL.EXE
    ↓
cmd.exe
    ↓
Command Execution
```

Another example:

```text
OUTLOOK.EXE
    ↓
powershell.exe
    ↓
Script Execution
```

The important part is the **process relationship**, not simply the presence of PowerShell or CMD.

---

## 5. Investigation

Review:

* User
* Computer
* Parent process
* Child process
* Command line
* Process path
* File involved
* Network connections
* Child processes
* Other endpoint alerts

Look for a chain such as:

```text
Email
  ↓
Office Application
  ↓
Command Interpreter
  ↓
Network Connection
  ↓
File Creation
```

---

## 6. False Positives & Tuning

Potential legitimate activity:

* Office automation
* Administrative scripts
* Enterprise management tools
* Approved macros
* Software deployment

Tune using:

* Approved applications
* Known automation scripts
* Administrative systems
* Service accounts
* Expected process relationships

---

## 7. Response

If malicious activity is confirmed:

1. Review the complete process tree.
2. Identify the originating file or application.
3. Analyze the command line.
4. Investigate network activity.
5. Search for the same process chain across endpoints.
6. Isolate the endpoint when appropriate.
7. Preserve relevant evidence.
8. Escalate according to the incident-response process.

---

## 8. Validation

Use an approved test environment to generate controlled process activity.

Verify that the detection captures:

* Parent process
* Child process
* Command line
* User
* Host
* Execution time

**Detection Status:** Ready for testing and tuning.
