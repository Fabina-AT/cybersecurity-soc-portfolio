# Sender / Domain Impersonation Detection

## 1. Detection Summary

**Use Case:** Sender / Domain Impersonation  
**Platform:** Microsoft Sentinel  
**Data Source:** Microsoft Defender for Office 365 / Email Security Logs  
**Severity:** High  
**MITRE ATT&CK:** T1566.002 – Spearphishing Link

### Description

Detects emails where the sender appears to impersonate a trusted organization, domain, executive, or internal user.

Attackers may use lookalike domains, display-name spoofing, or similar sender addresses to make phishing emails appear legitimate.

---

## 2. Detection Logic

```text id="7w4kq3"
Email Received
      ↓
Sender / Domain Analysis
      ↓
Trusted Identity Comparison
      ↓
Lookalike / Spoofing Indicator
      ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="x5m8nc"
EmailEvents
| where TimeGenerated >= ago(24h)
| where SenderFromDomain !endswith "company.com"
| where SenderDisplayName has_any (
    "CEO",
    "CFO",
    "HR",
    "IT",
    "Finance"
)
| project
    TimeGenerated,
    SenderFromAddress,
    SenderFromDomain,
    SenderDisplayName,
    RecipientEmailAddress,
    Subject,
    DeliveryAction
| order by TimeGenerated desc
```

> Replace `company.com` and the trusted display-name list with organization-specific values.

---

## 4. How It Works

The detection:

1. Reviews incoming email.
2. Checks the sender domain.
3. Compares the sender against trusted organizational identities.
4. Identifies messages using sensitive or commonly impersonated display names.
5. Generates candidates for investigation.

Display-name matching alone does not confirm impersonation.

---

## 5. Investigation

Review:

- Sender address
- Sender domain
- Display name
- Similarity to trusted domain
- SPF result
- DKIM result
- DMARC result
- Email authentication verdict
- URLs
- Attachments
- Recipient
- Email subject
- Previous communication with the sender

Pay particular attention to domains that visually resemble the organization's legitimate domain.

---

## 6. False Positives

Possible legitimate activity:

- External business partners
- Vendors
- Recruitment agencies
- Legitimate executives using personal accounts
- Third-party services
- Security awareness simulations

Maintain approved external sender and domain lists.

---

## 7. Response

If impersonation is confirmed:

1. Identify all recipients.
2. Search for similar sender addresses/domains.
3. Remove or quarantine malicious emails.
4. Block confirmed malicious domains or addresses.
5. Check whether users interacted with the message.
6. Investigate related URLs or attachments.
7. Investigate authentication activity if credentials may have been exposed.

**Detection Goal:** Identify sender and domain impersonation attempts that may be used to increase the credibility of phishing emails.
