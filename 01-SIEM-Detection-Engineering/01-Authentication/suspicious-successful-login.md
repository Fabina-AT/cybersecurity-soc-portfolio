# Suspicious Successful Login Detection

## 1. Detection Summary

**Use Case:** Suspicious Successful Login

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** High

**MITRE ATT&CK:** T1078 – Valid Accounts

### Description

Detects successful authentication that occurs after multiple failed login attempts from the same source IP and user within a short time period.

This may indicate that an attacker successfully obtained or guessed valid credentials.

---

## 2. Detection Logic

```text id="5b9n9f"
Multiple Failed Logins
        ↓
Successful Login
        ↓
Same User / Source IP
        ↓
Generate Alert
        ↓
SOC Investigation
```

**Example threshold:**

* 5+ failed attempts
* Followed by a successful login
* Within 30 minutes
* Same user and source IP

---

## 3. KQL Detection

```kql id="t2a4r5"
let FailedLogins =
    SigninLogs
    | where TimeGenerated >= ago(30m)
    | where ResultType != 0
    | summarize FailedAttempts = count()
        by UserPrincipalName, IPAddress;

SigninLogs
| where TimeGenerated >= ago(30m)
| where ResultType == 0
| join kind=inner FailedLogins
    on UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    FailedAttempts,
    AppDisplayName,
    Location
| order by TimeGenerated desc
```

---

## 4. Investigation

The analyst should review:

* User account and privilege level
* Source IP reputation
* Geographic location
* Device information
* Number of previous failures
* Authentication method
* MFA result
* Application accessed
* Activity after successful authentication

Particular attention should be given to privileged accounts and access to sensitive applications.

---

## 5. False Positives & Tuning

Potential false positives include:

* Users repeatedly entering incorrect passwords
* Password synchronization issues
* VPN authentication problems
* Mobile or cached credentials
* Application authentication failures

Tuning can include:

* Adjusting the failed-attempt threshold
* Limiting detection to external sources
* Excluding known authentication infrastructure
* Adding user and device risk
* Correlating MFA results

---

## 6. Response

If compromise is suspected:

1. Validate the user's recent activity.
2. Investigate the source IP and device.
3. Review activity after the successful login.
4. Check for privilege or configuration changes.
5. Revoke active sessions where appropriate.
6. Reset credentials if compromise is confirmed.
7. Escalate according to the incident-response process.

---

## 7. Validation

Test the detection using controlled authentication activity:

```text id="6s4tbh"
Failed Login
Failed Login
Failed Login
Failed Login
Failed Login
      ↓
Successful Login
      ↓
Detection Alert
```

Confirm that the alert identifies the correct:

* User
* Source IP
* Failed-attempt count
* Successful authentication
* Application

---

**Detection Status:** Ready for testing and tuning.

