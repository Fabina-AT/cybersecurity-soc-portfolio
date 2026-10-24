# Threat Hunting

This section contains practical, hypothesis-driven threat hunts focused on proactively finding suspicious activity that automated detections may miss, including malicious scripting, persistence, command-and-control, credential access, lateral movement, and cloud identity abuse.

## Hunting Objectives

The threat hunts are designed to identify:

* Encoded and obfuscated PowerShell execution
* Unusual parent-child process relationships
* Living-off-the-land binary abuse
* Persistence through scheduled tasks and registry run keys
* Beaconing and rare outbound connections
* Unusual authentication and login locations
* Credential access activity
* Lateral movement between hosts
* Malicious mailbox rules and email forwarding
* Suspicious cloud identity and permission changes
* Dormant or rarely used accounts becoming active
* Rare processes and unsigned binaries

## Data Sources

Threat hunts may use telemetry from:

* Microsoft Sentinel
* Microsoft Defender for Endpoint
* Microsoft Defender for Office 365
* Microsoft Entra ID
* Endpoint Detection and Response (EDR)
* Windows Security Events
* Sysmon
* Active Directory
* DNS logs
* Firewall logs
* Proxy logs
* Cloud audit logs
* Threat intelligence platforms

## Key Hunting Fields

The following fields are useful when building threat hunts:

| Field                 | Description                          |
| --------------------- | ------------------------------------ |
| Timestamp             | Time of the event                    |
| Device Name           | Host where the activity occurred     |
| Account Name          | User or service account involved     |
| Process Name          | Process that ran                     |
| Parent Process        | Process that launched it             |
| Command Line          | Full command executed                |
| File Path             | Location of the file                 |
| File Hash             | SHA256 of the file involved          |
| Signer                | Digital signature information        |
| Remote IP / URL       | External destination contacted       |
| Logon Type            | Interactive, remote, network, etc.   |
| Registry Key          | Registry path changed                |
| Event Frequency       | How often the activity occurs        |

## Hunting Use Cases

### 1. Encoded and Obfuscated PowerShell

Hunt for PowerShell launched with encoded commands, hidden windows, or download-and-run patterns.

File:

`encoded-powershell-hunt.md`

### 2. Unusual Parent-Child Processes

Hunt for Office, browser, or script host processes launching command shells and interpreters.

File:

`unusual-parent-child-processes.md`

### 3. Living-off-the-Land Binary Abuse

Hunt for abuse of built-in tools such as certutil, mshta, rundll32, and regsvr32.

File:

`lolbin-abuse-hunt.md`

### 4. Persistence Mechanisms

Hunt for new scheduled tasks, registry run keys, and startup items created by unusual processes.

File:

`persistence-hunt.md`

### 5. Beaconing and Rare Outbound Connections

Hunt for regular-interval connections and connections to rarely seen external destinations.

File:

`beaconing-hunt.md`

### 6. Unusual Authentication Activity

Hunt for logins from rare locations, impossible travel, and dormant accounts becoming active.

File:

`unusual-authentication-hunt.md`

### 7. Credential Access

Hunt for suspicious access to LSASS memory and credential dumping tools.

File:

`credential-access-hunt.md`

### 8. Lateral Movement

Hunt for accounts logging on to many hosts using RDP, SMB, or WinRM.

File:

`lateral-movement-hunt.md`

### 9. Mailbox Rule Abuse

Hunt for inbox rules that forward, delete, or hide messages.

File:

`mailbox-rule-abuse-hunt.md`

### 10. Cloud Identity Abuse

Hunt for unusual IAM changes, new access keys, and permission escalation in cloud environments.

File:

`cloud-identity-abuse-hunt.md`

## Hunting Approach

Each threat hunt follows a hypothesis-driven process:

1. Define the hypothesis
2. Identify the data sources needed
3. Build the hunting query
4. Establish a baseline of normal behavior
5. Review the results and filter known-good activity
6. Investigate suspicious findings
7. Escalate confirmed incidents
8. Document the findings and conclusion
9. Convert useful hunts into detections

## Correlation Opportunities

Hunting results can be correlated with:

* Endpoint telemetry
* EDR alerts
* Sign-in logs
* Email events
* DNS activity
* Proxy logs
* Firewall logs
* Cloud activity
* Privilege changes
* Threat intelligence

## Threat Hunting Considerations

Threat hunts should be evaluated for:

* Quality of the hypothesis
* Data availability and retention
* Time-window selection
* Baseline accuracy
* False-positive rate
* Known administrative tools and allowlists
* Query performance
* Coverage of the targeted technique
* Repeatability

## MITRE ATT&CK

Relevant ATT&CK techniques may include:

* **T1059 – Command and Scripting Interpreter**
* **T1218 – System Binary Proxy Execution**
* **T1053 – Scheduled Task/Job**
* **T1547 – Boot or Logon Autostart Execution**
* **T1071 – Application Layer Protocol**
* **T1078 – Valid Accounts**
* **T1003 – OS Credential Dumping**
* **T1021 – Remote Services**
* **T1114 – Email Collection**
* **T1098 – Account Manipulation**

Specific sub-techniques should be mapped according to the behavior being hunted.

## Analyst Outcome

Each hunt should be classified based on the available evidence.

Possible outcomes include:

* No suspicious activity found
* Benign activity
* Expected administrative activity
* Suspicious activity
* Confirmed malicious activity
* Requires further investigation

The analyst should document the hypothesis, queries, findings, and final disposition.

## Hunting Improvement

Threat hunting should be continuously improved through:

* Hypothesis refinement
* Query tuning
* Allowlist maintenance
* Additional telemetry
* Conversion of successful hunts into detection rules
* Correlation with endpoint and network activity
* Lessons learned from each hunt
* Regular review of hunting coverage
