# Brute-Force Attack Investigation

## Incident Summary
The SOC received an alert for repeated failed login attempts against an employee account.

## Investigation
- Reviewed authentication logs and source IP details.
- Checked whether a successful login occurred after the failures.
- Examined MFA results and unusual account activity.
- Checked whether other accounts were targeted.

## Findings
Repeated failures were observed from an unfamiliar source. Further investigation was required to determine whether unauthorized access succeeded.

## Response
- Escalated the incident for investigation.
- Recommended credential reset and session revocation if compromise was confirmed or reasonably suspected.
- Reviewed other accounts for related activity.
- Continued monitoring for recurrence.

## Outcome
**Status:** Pending investigation  
**Evidence:** Authentication logs and sign-in records  
**Lesson learned:** Correlating failed logins with successful sign-ins helps establish whether an account may have been compromised.

*Portfolio note: This is a simulated case study. Replace the findings and outcome with verified results from your lab before presenting it as a completed investigation.*


