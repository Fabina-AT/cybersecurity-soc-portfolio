# Security Tool Tampering Detection

## 1. Detection Summary

**Use Case:** Security Tool Tampering
**Platform:** Microsoft Sentinel
**Data Source:** Windows Security Events (`4688`)
**Severity:** High
**MITRE ATT&CK:** T1562.001 – Impair Defenses

### Description

Detects attempts to stop, disable, or modify security-related services using command-line tools.

---

## 2. Detection Logic

```text id="2egx6t"
Process Creation
      ↓
Security Service Modification
      ↓
Suspicious Command
      ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="g5d1tb"
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| where CommandLine has_any (
    "sc stop",
    "sc delete",
    "net stop",
    "Set-MpPreference"
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

### How it works

The query looks for commands commonly used to modify or stop security protections.

Example:

```text id="yqzj52"
cmd.exe
   ↓
sc stop <security service>
   ↓
Security Protection Modified
   ↓
Alert
```

---

## 4. Investigation

Review:

* User/account
* Host
* Command line
* Parent process
* Target security service
* Process tree
* Related malware alerts
* Recent PowerShell activity
* Other endpoint changes

---

## 5. False Positives & Tuning

Possible legitimate activity:

* Security software maintenance
* IT administration
* Approved troubleshooting
* Endpoint management

Tune using approved administrators, management systems, and maintenance windows.

---

## 6. Response

If unauthorized tampering is confirmed:

1. Identify the affected endpoint.
2. Review the process tree.
3. Determine what security control was modified.
4. Restore security protections when appropriate.
5. Investigate related malicious activity.
6. Isolate the endpoint if compromise is suspected.
7. Escalate according to the incident-response process.

**Detection Status:** Ready for testing and tuning.
