# Suspicious LOLBin Execution Detection

## 1. Detection Summary

**Use Case:** Suspicious LOLBin Execution

**Platform:** Microsoft Sentinel

**Data Source:** Windows Security Events (`4688`)

**Severity:** High

**MITRE ATT&CK:** T1218 – System Binary Proxy Execution

### Description

Detects execution of legitimate Windows binaries that can be abused to execute commands, scripts, or malicious files.

Examples include:

* `mshta.exe`
* `regsvr32.exe`
* `rundll32.exe`
* `certutil.exe`
* `bitsadmin.exe`

---

## 2. Detection Logic

```text
Windows Process
      ↓
Known LOLBin
      ↓
Review Command Line
      ↓
Check Parent Process
      ↓
Generate Alert
      ↓
SOC Investigation
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| where NewProcessName has_any (
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe"
)
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    CommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection looks for execution of commonly abused Windows utilities.

For example:

```text
WINWORD.EXE
     ↓
mshta.exe
     ↓
Script Execution
```

Or:

```text
powershell.exe
     ↓
certutil.exe
     ↓
File Activity
```

The presence of a LOLBin **does not automatically mean malicious activity**. The analyst should investigate the execution context.

---

## 5. Investigation

Review:

* User
* Host
* Process name
* Command line
* Parent process
* Child processes
* File path
* Network connections
* Related endpoint alerts
* Authentication activity

Look for combinations such as:

```text
Office Application
      ↓
LOLBin
      ↓
Network Connection
      ↓
File Creation
```

Multiple suspicious behaviors increase the priority of the investigation.

---

## 6. False Positives & Tuning

Legitimate activity may include:

* Software installation
* System administration
* Windows components
* Enterprise management tools
* Approved scripts

Tune using:

* Known administrative hosts
* Approved applications
* Expected command lines
* Service accounts
* Known software-management processes

Avoid simply excluding the LOLBin executable globally.

---

## 7. Response

If malicious activity is confirmed:

1. Analyze the command line.
2. Review the complete process tree.
3. Identify files created or executed.
4. Investigate network connections.
5. Search for the same activity across other endpoints.
6. Isolate the endpoint when appropriate.
7. Preserve relevant evidence.
8. Escalate according to the incident-response process.

---

## 8. Validation

Test using an approved lab environment and verify that the detection captures:

* LOLBin name
* Command line
* Parent process
* User
* Host
* Execution time

**Detection Status:** Ready for testing and tuning.
