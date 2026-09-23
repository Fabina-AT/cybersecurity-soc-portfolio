# Brute-Force Authentication Detection

## 1. Detection Summary

**Use Case:** Brute-Force Authentication

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** Medium

**MITRE ATT&CK:** T1110 – Brute Force

### Description

Detects repeated failed authentication attempts against a user account within a short time period. The detection helps identify potential password-guessing activity and possible account compromise.

---

## 2. Detection Logic

**Threshold:** 10+ failed sign-in attempts within 10 minutes for the same user.

```text
Failed Sign-ins
      ↓
Group by User
      ↓
10+ Attempts / 10 Minutes
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
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    SourceIPs = make_set(IPAddress, 10)
    by UserPrincipalName
| where FailedAttempts >= 10
| project UserPrincipalName, FailedAttempts,
          FirstAttempt, LastAttempt, SourceIPs
| order by FailedAttempts desc
```

---

## 4. Investigation

When the alert triggers, the analyst reviews:

* Targeted user and account type
* Source IP and reputation
* Authentication location
* Number and timing of failed attempts
* Applications being accessed
* Successful login following failures
* Related endpoint or cloud activity

A successful authentication following repeated failures should be investigated for possible account compromise.

---

## 5. False Positives & Tuning

Common false positives include:

* Incorrect passwords
* Expired credentials
* VPN issues
* Service accounts
* Application authentication failures

Tuning may include adjusting the threshold, excluding approved infrastructure, and separating service-account activity.

---

## 6. Response

If malicious activity is confirmed:

1. Investigate the source IP and affected account.
2. Review successful authentication and subsequent activity.
3. Reset credentials if compromise is confirmed.
4. Revoke sessions where appropriate.
5. Escalate according to the incident-response process.

---

## 7. Validation

The detection should be tested using controlled failed authentication attempts to verify:

* Required logs are collected
* Detection triggers at the defined threshold
* Alert contains sufficient investigation context
* Legitimate authentication activity does not create excessive alerts

---

**Detection Status:** Ready for testing and tuning.


