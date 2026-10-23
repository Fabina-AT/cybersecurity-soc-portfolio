# Brute-Force Attack Investigation

## Case Details

| Field | Details |
|---|---|
| Type | Lab simulation |
| Severity | High |
| MITRE ATT&CK | T1110.001, T1110.003, T1078 |

## Incident Summary

The SOC received a Microsoft Sentinel alert for repeated failed sign-ins against an employee account. The failures came from a single unfamiliar IP that also tried several other accounts. One sign-in then succeeded, so the account was treated as compromised and contained.

## Investigation

- Reviewed authentication logs and source IP details.
- Checked whether a successful login occurred after the failures.
- Examined MFA results and unusual account activity.
- Checked whether other accounts were targeted.

## Detection Queries

### Failed sign-in volume by source IP

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize Failures = count(), Accounts = dcount(UserPrincipalName) by IPAddress
| where Failures > 20
| order by Failures desc
```

### Success following the failures

```kql
let attackerIPs = SigninLogs
    | where TimeGenerated > ago(24h) and ResultType != 0
    | summarize Failures = count() by IPAddress
    | where Failures > 20
    | project IPAddress;
SigninLogs
| where TimeGenerated > ago(24h)
| where IPAddress in (attackerIPs) and ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, AuthenticationRequirement
```

## Timeline

| Time | Event | Data Source |
|---|---|---|
| 02:10 | Failed sign-ins begin from 198.51.100.23 | SigninLogs |
| 02:10–02:35 | About 60 failures across 5 accounts, a password spraying pattern | SigninLogs |
| 02:41 | Successful sign-in on one account from the same IP | SigninLogs |
| 02:42 | Sign-in used a legacy protocol with no MFA challenge | SigninLogs |
| 02:50 | Sentinel alert raised | Sentinel |

## Findings

Repeated failures came from an unfamiliar source targeting multiple accounts, which points to password spraying. One account then signed in from the same IP, outside the user's normal location and without an MFA prompt because the sign-in used a legacy protocol. Root cause: a weak password combined with legacy authentication that bypassed MFA.

## Response

- Disabled the account, revoked all sessions and reset the password.
- Blocked the source IP.
- Reviewed the mailbox for new inbox rules and forwarding (none found).
- Checked the other 4 targeted accounts, with no successful sign-ins, and reset their passwords as a precaution.
- Monitored all five accounts for 72 hours.

## Outcome

**Status:** Contained, no data loss confirmed

**Evidence:** Authentication logs and sign-in records

## Lessons Learned

Correlating failed logins with successful sign-ins from the same source shows whether an account was compromised. Recommend blocking legacy authentication, enforcing MFA for all users, and keeping the correlation query as a scheduled analytics rule.

## IOCs

- **IP:** `198.51.100.23` - brute-force and spray source
- **Protocol:** Legacy authentication (IMAP/SMTP) - bypassed MFA

## Portfolio Note

This is a simulated case study. Replace the figures, times and findings with verified results from your lab before presenting it as a completed investigation.
