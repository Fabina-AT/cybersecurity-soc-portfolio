Phishing to Account Compromise Investigation
Case Details
Type: Lab simulation
Severity: High
MITRE ATT&CK: T1566.002, T1078, T1114.003
Incident Summary

A user clicked a link in a credential-harvesting email and entered their Microsoft 365 password on a fake sign-in page. The attacker signed in from an unfamiliar IP and created a mailbox rule to hide replies. The account was contained within 1 hour of the alert, and no data exfiltration was confirmed.

Investigation
Reviewed the Sentinel alert and the sign-in logs for the account.
Checked the clicked URL and sign-in IP in VirusTotal.
Opened the URL in Any.Run to confirm a fake login form.
Confirmed the user normally signs in from the UAE only.
Checked the mailbox for new inbox rules and forwarding.
Searched other mailboxes for the same sender and URL.
Detection Queries

Sign-in after a URL click:

kql
let clicks = UrlClickEvents
    | where ActionType == "ClickAllowed"
    | project ClickTime = Timestamp, AccountUpn, Url;
SigninLogs
| where ResultType == 0
| where RiskLevelDuringSignIn in ("medium", "high") or Location != "AE"
| join kind=inner (clicks) on $left.UserPrincipalName == $right.AccountUpn
| where TimeGenerated between (ClickTime .. ClickTime + 2h)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, Url

Mailbox rule check:

kql
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where UserId == "user@contoso.example"
| project TimeGenerated, UserId, ClientIP, Parameters
Timeline
09:02 - Phishing email delivered - Defender for Office 365
09:07 - User clicked the link - UrlClickEvents
09:08 - Credentials submitted to fake page - Any.Run analysis
09:15 - Successful sign-in from 203.0.113.45 - SigninLogs
09:19 - Inbox rule created to move replies to RSS Feeds folder - OfficeActivity
09:40 - Sentinel alert raised - Sentinel
Findings

The domain was newly registered and flagged as phishing by several vendors. The sign-in came from a foreign IP shortly after the click, and a mailbox rule was created to hide replies. Four other recipients got the same email and one other user clicked, with no sign-in. Root cause: credential theft through phishing, with no MFA enforced on the account.

Response
Disabled the account and revoked all active sessions.
Reset the password.
Blocked the phishing domain and sender at the email gateway.
Purged the email from the 4 other mailboxes.
Deleted the malicious inbox rule and checked for forwarding (none found).
Enabled MFA, re-enabled the account and monitored it for 72 hours.
Outcome

Status: Contained, no data loss confirmed Evidence: Sign-in logs, email logs, Office activity logs and sandbox report

Lessons Learned

Correlating URL clicks with sign-ins shows account compromise quickly. Recommend enforcing MFA for all users, keeping the correlation query as a scheduled analytics rule, and adding a mailbox rule check to the compromised-account checklist.

IOCs
Domain: m365-login-verify[.]example - phishing page
IP: 203.0.113.45 - attacker sign-in
Sender: no-reply@secure-docs[.]example - phishing sender
Subject: Action required: document shared with you - phishing email
Portfolio Note

This is a simulated case study. Replace the figures, times and findings with verified results from your lab before presenting it as a completed investigation.
