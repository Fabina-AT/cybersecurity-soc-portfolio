# Password Spraying Detection

## 1. Detection Summary

**Use Case:** Password Spraying

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** Medium

**MITRE ATT&CK:** T1110.003 – Password Spraying

### Description

Detects authentication failures from a common source IP against multiple user accounts within a short time period. This behavior may indicate password spraying, where an attacker attempts a small number of commonly used passwords across many accounts.

---

## 2. Detection Logic

**Threshold:** 5+ targeted users from the same source IP within 10 minutes, with failed authentication attempts.

```text
Authentication Failures
        ↓
Group by Source IP
        ↓
Multiple User Accounts
        ↓
Threshold Exceeded
        ↓
Generate Alert
        ↓
SOC Investigation
```

---

## 3. KQL Detection

```kql
SigninLogs
| where TimeGenerated >= ago(10m)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 20),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress
| where TargetedUsers >= 5
| project
    IPAddress,
    TargetedUsers,
    FailedAttempts,
    Users,
    FirstAttempt,
    LastAttempt
| order by TargetedUsers desc
```

---

## 4. Investigation

The analyst should review:

* Source IP and reputation
* Number of targeted accounts
* Usernames targeted
* Authentication locations
* Authentication applications
* Successful logins from the source IP
* Privileged accounts among targeted users
* Related endpoint or cloud activity

A successful authentication from the same source should be treated as a priority investigation point.

---

## 5. False Positives & Tuning

Potential false positives include:

* Misconfigured applications
* Authentication services
* VPN infrastructure
* Shared systems
* Service accounts
* Legitimate authentication failures

Tuning may include trusted-source exclusions, service-account handling, and adjustment of the targeted-user threshold.

---

## 6. Response

If malicious activity is confirmed:

1. Investigate the source IP.
2. Identify affected accounts.
3. Check for successful authentication.
4. Review activity following successful authentication.
5. Reset credentials for confirmed compromised accounts.
6. Revoke sessions where appropriate.
7. Escalate according to the incident-response process.

---

## 7. Validation

Validate the detection using controlled authentication attempts against multiple test accounts.

Confirm that:

* Multiple targeted users are detected.
* The source IP is captured.
* The alert contains sufficient investigation context.
* Legitimate authentication infrastructure does not generate excessive alerts.

---

**Detection Status:** Ready for testing and tuning.
