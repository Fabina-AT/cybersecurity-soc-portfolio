# Email Thread Hijacking Detection

## 1. Detection Summary

**Use Case:** Email Thread Hijacking  
**Platform:** Microsoft Sentinel  
**Data Source:** Microsoft Defender for Office 365 / Email Security Logs  
**Severity:** High  
**MITRE ATT&CK:** T1566.002 – Spearphishing Link

### Description

Detects suspicious emails sent as replies or continuations of existing business conversations.

Attackers may compromise an email account and use existing conversations to send malicious links, attachments, or requests that appear legitimate to the recipient.

---

## 2. Detection Logic

```text
Existing Email Thread
        ↓
Unexpected Reply
        ↓
Suspicious URL / Attachment
        ↓
Sender Account Validation
        ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="x7k31p"
EmailEvents
| where TimeGenerated >= ago(24h)
| where ThreatTypes has_any ("Phish", "Malware")
| where Subject startswith "RE:"
| project
    TimeGenerated,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DeliveryAction
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection:

1. Reviews recent email activity.
2. Identifies messages appearing to be replies.
3. Checks whether the message was classified as phishing or malware.
4. Flags suspicious messages for investigation.

A `RE:` subject alone does not indicate thread hijacking. The sender's account activity and message content should be correlated.

---

## 5. Investigation

Review:

- Sender account
- Recipient
- Email subject
- Previous messages in the thread
- URLs
- Attachments
- Sender authentication
- Sender sign-in activity
- Source IP
- MFA activity
- Similar messages sent from the account

Look for unexpected changes in the conversation, unusual URLs, payment requests, credential requests, or malicious attachments.

---

## 6. False Positives

Possible legitimate activity:

- Normal business replies
- Automated email systems
- Security awareness simulations
- Approved external communication

Validate the sender and message context before classification.

---

## 7. Response

If account compromise or malicious activity is confirmed:

1. Identify affected recipients.
2. Remove or quarantine malicious messages.
3. Investigate the sender's sign-in activity.
4. Review recent mailbox activity.
5. Search for additional malicious messages.
6. Block confirmed malicious URLs or attachments.
7. Protect the compromised account.
8. Investigate related activity across the environment.

**Detection Goal:** Identify malicious emails that abuse existing conversations to increase phishing credibility and bypass user suspicion.
