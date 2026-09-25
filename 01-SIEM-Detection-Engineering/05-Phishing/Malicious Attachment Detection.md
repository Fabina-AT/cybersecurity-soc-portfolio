# Malicious Attachment Detection

## 1. Detection Summary

**Use Case:** Malicious Email Attachment  
**Platform:** Microsoft Sentinel  
**Data Source:** Microsoft Defender for Office 365 / Email Security Logs  
**Severity:** High  
**MITRE ATT&CK:** T1566.001 – Spearphishing Attachment

### Description

Detects emails containing attachments classified as malicious or associated with malware.

Attackers commonly use weaponized documents, scripts, archives, and executable files to deliver malware through email.

---

## 2. Detection Logic

```text id="q6z8sk"
Email Received
      ↓
Attachment Detected
      ↓
Malware Classification
      ↓
Sender / Recipient Review
      ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="j7q2mv"
EmailAttachmentInfo
| where TimeGenerated >= ago(24h)
| where ThreatType has_any ("Malware", "Phish")
| project
    TimeGenerated,
    NetworkMessageId,
    FileName,
    FileType,
    ThreatType
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection:

1. Reviews email attachment activity.
2. Filters attachments associated with malware or phishing.
3. Captures the filename and file type.
4. Uses the message ID to correlate the attachment with the original email.

The attachment verdict should be validated using Microsoft Defender and additional endpoint evidence.

---

## 5. Investigation

Review:

- Attachment filename
- File type
- Sender
- Recipient
- Email subject
- File hash
- Malware classification
- Delivery action
- Whether the attachment was opened
- Endpoint activity
- Process creation
- Network connections

Search for the same filename or hash across the environment.

---

## 6. False Positives

Possible causes:

- Security testing
- Malware simulation exercises
- Legitimate files incorrectly classified
- Internal testing
- Business applications sending unusual file types

Validate the attachment before containment.

---

## 7. Response

If malicious activity is confirmed:

1. Identify all recipients.
2. Search for the attachment hash across the environment.
3. Remove or quarantine affected emails.
4. Block the malicious file/hash where appropriate.
5. Determine whether users opened the attachment.
6. Investigate endpoint process activity.
7. Isolate affected endpoints if malware execution is confirmed.
8. Investigate persistence and additional compromise indicators.

**Detection Goal:** Identify malicious email attachments and correlate delivery with endpoint activity to determine potential malware execution.
