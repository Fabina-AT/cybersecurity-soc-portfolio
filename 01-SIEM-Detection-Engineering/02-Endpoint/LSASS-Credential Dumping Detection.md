# Credential Dumping Detection

## 1. Detection Summary

**Use Case:** Credential Dumping / LSASS Access

**Platform:** Microsoft Sentinel

**Data Source:** Windows Security Events (`4688`)

**Severity:** High

**MITRE ATT&CK:** T1003 – OS Credential Dumping

### Description

Detects suspicious processes and command-line activity that may indicate attempts to access or dump credentials from the Windows LSASS process.

---

## 2. Detection Logic

```text
Process Creation
      ↓
Credential Dumping Indicator
      ↓
LSASS / Memory Access
      ↓
Review Process + User Context
      ↓
Generate Alert
      ↓
SOC Investigation
```

Common indicators include:

* `lsass.exe`
* `procdump`
* `comsvcs.dll`
* `MiniDump`
* `sekurlsa`
* `nanodump`

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| extend SuspiciousActivity = CommandLine has_any (
    "procdump",
    "comsvcs.dll",
    "MiniDump",
    "sekurlsa",
    "nanodump"
)
| where SuspiciousActivity
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection searches process-creation events for known credential-dumping indicators.

Example:

```text
Attacker / Malicious Process
          ↓
    Access LSASS
          ↓
   Credential Dump
          ↓
Credentials Potentially Exposed
```

A matching command line does **not automatically confirm compromise**. The analyst should investigate the complete process context.

---

## 5. Investigation

Review:

* User account
* Host
* Process name
* Parent process
* Command line
* Process path
* File creation
* Network connections
* Other security alerts
* Recent authentication activity
* Privileged account activity

Pay particular attention when the activity is performed by:

* A standard user
* An unexpected administrator
* An unusual process
* A process running from a temporary or user-writable directory

---

## 6. False Positives & Tuning

Possible legitimate activity:

* Approved security tools
* Endpoint detection software
* Authorized forensic investigation
* System administration

Tune using:

* Approved security tools
* Known administrative accounts
* Approved management servers
* Expected command lines

Avoid excluding all activity involving `lsass.exe`.

---

## 7. Response

If credential dumping is confirmed:

1. Identify the affected endpoint.
2. Review the complete process tree.
3. Determine which credentials may have been exposed.
4. Investigate authentication activity from the affected account.
5. Isolate the endpoint when appropriate.
6. Reset affected credentials where required.
7. Search for similar activity across other endpoints.
8. Preserve relevant evidence.
9. Escalate according to the incident-response process.

---

## 8. Validation

Use an approved lab environment and authorized security-testing tools.

Verify that the detection captures:

* Host
* User
* Process
* Parent process
* Command line
* Execution time

**Detection Status:** Ready for testing and tuning.
