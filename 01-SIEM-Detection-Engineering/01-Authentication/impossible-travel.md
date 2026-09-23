# Impossible Travel Detection

## 1. Detection Summary

**Use Case:** Impossible Travel

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** Medium

**MITRE ATT&CK:** T1078 – Valid Accounts

### Description

Detects successful authentication events from geographically distant locations within a time period that would be unrealistic for a user to physically travel between.

This can indicate compromised credentials or unauthorized account access.

---

## 2. Detection Logic

```text id="8g2xkd"
Successful Login
       ↓
Location A
       ↓
Short Time Interval
       ↓
Location B
       ↓
Unrealistic Travel Distance
       ↓
Generate Alert
```

Example:

```text
10:00 → Login from Dubai
10:45 → Login from London
```

The activity should be investigated because the time between the two locations may be insufficient for physical travel.

---

## 3. KQL Detection

Microsoft Entra ID provides geographic information in `SigninLogs`. A simple approach is to identify users authenticating from multiple countries within a short time period.

```kql id="q6z1sj"
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| summarize
    LoginCount = count(),
    Countries = make_set(LocationDetails.countryOrRegion),
    IPAddresses = make_set(IPAddress),
    FirstLogin = min(TimeGenerated),
    LastLogin = max(TimeGenerated)
    by UserPrincipalName
| where array_length(Countries) > 1
| project
    UserPrincipalName,
    LoginCount,
    Countries,
    IPAddresses,
    FirstLogin,
    LastLogin
```

> This is a hunting query for identifying users with successful logins from multiple countries. Production impossible-travel detection should also consider the exact login timestamps and geographic distance between events.

---

## 4. Investigation

The analyst should review:

* User account
* Source IP addresses
* Login locations
* Login timestamps
* Device information
* Authentication method
* MFA result
* VPN usage
* User's normal login pattern
* Activity following the authentication

---

## 5. False Positives & Tuning

Common causes include:

* VPN usage
* Corporate proxies
* Cloud services
* Mobile networks
* Remote workers
* Travel
* Incorrect GeoIP information

Tuning should consider known VPN ranges, corporate infrastructure, trusted locations, and normal user travel patterns.

---

## 6. Response

If unauthorized access is suspected:

1. Validate the user's activity.
2. Investigate the source IPs and devices.
3. Review recent authentication activity.
4. Check for suspicious activity after login.
5. Revoke sessions where appropriate.
6. Reset credentials if compromise is confirmed.
7. Escalate according to the incident-response process.

---

## 7. Validation

Test using controlled authentication events from different geographic locations.

Confirm that the investigation identifies:

* User
* Source IP
* Location
* Authentication time
* Device
* Authentication method

---

**Detection Status:** Ready for testing and tuning.
