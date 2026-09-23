# Authentication Detection

This section contains practical SIEM detection use cases focused on identifying suspicious authentication activity, credential attacks, account compromise, and identity-based threats.

## Detection Objectives

The authentication detections are designed to identify:

* Brute-force authentication attacks
* Password spraying
* Credential attacks
* Suspicious successful logins
* Impossible travel
* Unusual login locations
* Privileged account authentication
* Authentication from suspicious IP addresses
* MFA-related anomalies
* Account takeover indicators
* Dormant account activity
* Remote authentication anomalies

## Data Sources

Authentication detections may use telemetry from:

* Windows Security Events
* Microsoft Entra ID
* Active Directory
* VPN authentication logs
* Identity Provider (IdP) logs
* Microsoft Defender
* Endpoint Detection and Response (EDR)
* Firewall logs
* Proxy logs
* Cloud authentication logs
* SIEM normalized authentication data

## Key Authentication Fields

The following fields are useful when developing authentication detections:

| Field                 | Description                        |
| --------------------- | ---------------------------------- |
| Timestamp             | Time of authentication event       |
| Username              | Account involved                   |
| Source IP             | Originating IP address             |
| Destination           | Target system or service           |
| Authentication Result | Success or failure                 |
| Authentication Method | Password, MFA, certificate, etc.   |
| Device Name           | Device used for authentication     |
| Source Location       | Geographic location                |
| ASN                   | Network/provider information       |
| User Agent            | Client/application information     |
| Failure Reason        | Reason for authentication failure  |
| MFA Result            | MFA success, failure, or challenge |
| Risk Level            | Identity/security risk information |

## Detection Use Cases

### 1. Brute Force

Detect repeated authentication failures against a user or system within a defined time window.

File:

`brute-force-detection.md`

### 2. Password Spraying

Detect authentication attempts where a single source attempts a small number of passwords across multiple user accounts.

File:

`password-spraying.md`

### 3. Suspicious Successful Login

Identify successful authentication following suspicious authentication failures or other risk indicators.

File:

`suspicious-successful-login.md`

### 4. Impossible Travel

Identify authentication activity where a user appears to authenticate from geographically distant locations within an unrealistic time period.

File:

`impossible-travel.md`

### 5. Privileged Account Login

Monitor authentication activity involving privileged or administrative accounts.

File:

`privileged-account-login.md`

## Investigation Approach

When investigating an authentication alert, the SOC analyst should examine:

1. User account
2. Source IP address
3. Destination system
4. Authentication result
5. Authentication method
6. Number of failed attempts
7. Successful authentication following failures
8. Source location
9. ASN and network provider
10. Device information
11. User agent
12. MFA activity
13. Previous authentication history
14. Normal user behavior
15. Related endpoint activity
16. Threat-intelligence reputation

## Correlation Opportunities

Authentication events can be correlated with:

* Endpoint telemetry
* EDR alerts
* VPN activity
* DNS activity
* Proxy logs
* Firewall logs
* Cloud activity
* Privilege changes
* Password changes
* MFA events
* Threat intelligence

## Detection Engineering Considerations

Authentication detections should be evaluated for:

* Detection accuracy
* False-positive rate
* Threshold selection
* Time-window selection
* Data quality
* Log availability
* User and service-account baselines
* Known corporate IP ranges
* VPN infrastructure
* Authentication service accounts
* Geographic accuracy
* Detection performance

## MITRE ATT&CK

Relevant authentication-related ATT&CK techniques may include:

* **T1110 – Brute Force**
* **T1078 – Valid Accounts**
* **T1098 – Account Manipulation**
* **T1136 – Create Account**

Specific sub-techniques should be mapped according to the behavior being detected.

## Analyst Outcome

Each alert should be investigated and classified based on the available evidence.

Possible outcomes include:

* Benign activity
* Expected administrative activity
* Suspicious activity
* Confirmed malicious activity
* False positive
* Requires further investigation

The analyst should document the evidence, investigation steps, and final disposition.

## Detection Improvement

Detection performance should be continuously improved through:

* Threshold tuning
* False-positive analysis
* Threat-intelligence enrichment
* User/entity baselining
* Additional telemetry
* Correlation with endpoint and network activity
* Detection testing
* Incident feedback
* Regular review of detection effectiveness
