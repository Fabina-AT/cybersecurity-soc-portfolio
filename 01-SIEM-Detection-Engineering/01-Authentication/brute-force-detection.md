# Brute-Force Authentication Detection

## 1. Detection Overview

This detection identifies potential brute-force authentication activity by detecting multiple failed authentication attempts from the same source against one or more user accounts within a defined time window.

The detection is designed from a SOC detection-engineering perspective and can be adapted for SIEM platforms such as Microsoft Sentinel and Splunk.

---

## 2. Threat Scenario

An attacker may repeatedly attempt different passwords against a user account to gain unauthorized access.

Typical attack flow:

```text
Attacker
   |
   | Multiple authentication attempts
   v
Authentication Service
   |
   | Failed logins
   v
SIEM
   |
   | Correlation / Threshold
   v
SOC Alert
   |
   v
Analyst Investigation
```

A successful authentication following a high volume of failures may indicate potential account compromise and should be investigated.

---

## 3. Detection Objective

The objective is to identify:

* Repeated failed authentication attempts
* Password brute-force activity
* Automated credential attacks
* Potential account compromise attempts
* Suspicious authentication sources

---

## 4. Detection Logic

The detection identifies:

> Multiple failed authentication attempts from the same source IP against the same user within a defined time window.

Example detection condition:

```text
Failed authentication attempts >= 10
AND
Time window = 10 minutes
AND
Same source IP
AND
Same username
```

The threshold should be tuned according to the organization's normal authentication behavior.

---

## 5. Data Sources

Potential telemetry sources include:

* Windows Security Events
* Microsoft Entra ID
* Active Directory
* VPN authentication logs
* Identity Provider logs
* Microsoft Defender
* EDR telemetry
* SIEM authentication events

---

## 6. Required Log Fields

The detection should ideally contain:

| Field                 | Description                       |
| --------------------- | --------------------------------- |
| Timestamp             | Time of authentication attempt    |
| Username              | Target user account               |
| Source IP             | Originating IP address            |
| Destination           | Target system/service             |
| Authentication Result | Success or failure                |
| Authentication Method | Password, MFA, certificate, etc.  |
| Device Name           | Source device                     |
| Failure Reason        | Reason for authentication failure |
| Source Location       | Geographic location               |
| ASN                   | Network/provider information      |
| User Agent            | Client/application information    |

---

# 7. Microsoft Sentinel – KQL

The following example detects repeated failed authentication events.

```kql
SigninLogs
| where TimeGenerated >= ago(10m)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    SourceIPs = make_set(IPAddress, 10),
    Applications = make_set(AppDisplayName, 10)
    by UserPrincipalName
| where FailedAttempts >= 10
| project
    UserPrincipalName,
    FailedAttempts,
    FirstAttempt,
    LastAttempt,
    SourceIPs,
    Applications
| order by FailedAttempts desc
```

### KQL Logic

The query:

1. Looks at the last 10 minutes.
2. Filters unsuccessful sign-ins.
3. Groups events by user.
4. Counts failed authentication att

