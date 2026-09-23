# SIEM & Detection Engineering

This repository contains practical SIEM detection engineering use cases developed from a Security Operations Center (SOC) perspective.

The objective is to demonstrate the complete detection lifecycle, from threat identification and telemetry requirements through detection development, validation, tuning, deployment, and continuous improvement.

## Experience Focus

The repository focuses on practical SOC capabilities including:

* SIEM monitoring
* Detection engineering
* Alert triage
* Security event correlation
* Threat hunting
* Incident investigation
* Detection tuning
* False-positive reduction
* MITRE ATT&CK mapping
* Threat intelligence enrichment
* Cloud security monitoring
* Identity security
* Endpoint detection
* Network security monitoring
* Detection validation
* Security automation

## Detection Categories

### Authentication

* Brute-force attacks
* Suspicious successful authentication
* Impossible travel
* Account compromise
* Privileged account activity
* Authentication anomalies

### Endpoint

* Suspicious PowerShell
* Command and scripting activity
* Process anomalies
* Persistence
* Credential access
* Ransomware behavior

### Network

* External RDP
* SSH attacks
* Port scanning
* Suspicious outbound connections
* Command and control activity
* Data exfiltration

### Cloud

* AWS CloudTrail monitoring
* Azure Entra ID monitoring
* Suspicious cloud API activity
* MFA anomalies
* IAM changes
* Privilege escalation

### Identity

* MFA abuse
* New privileged accounts
* Suspicious OAuth activity
* Unusual authentication
* Credential misuse
* Account takeover indicators

## Detection Engineering Lifecycle

```text
Threat / Attack Scenario
        ↓
Threat Intelligence
        ↓
MITRE ATT&CK Mapping
        ↓
Detection Hypothesis
        ↓
Telemetry Requirements
        ↓
Detection Development
        ↓
Testing & Validation
        ↓
False-Positive Analysis
        ↓
Tuning
        ↓
Deployment
        ↓
Monitoring
        ↓
Continuous Improvement
```

## Detection Documentation

Each detection documents:

* Detection objective
* Threat scenario
* Data sources
* Required fields
* Detection logic
* SIEM query
* MITRE ATT&CK mapping
* Severity considerations
* False positives
* Investigation workflow
* Enrichment requirements
* Response recommendations
* Testing methodology
* Tuning considerations
* Detection limitations

## SIEM Technologies

Examples in this repository may include:

* Microsoft Sentinel / KQL
* Splunk / SPL
* Microsoft Defender
* Windows Event Logs
* Sysmon
* AWS CloudTrail
* Azure Entra ID
* Azure Activity Logs
* Firewall logs
* DNS logs
* Proxy logs
* EDR telemetry

## Detection Quality

Detection quality is evaluated using:

* Signal-to-noise ratio
* False-positive rate
* Telemetry availability
* Detection coverage
* Investigation value
* Query performance
* Maintainability
* Attack-technique coverage

## Goal

The goal is to demonstrate practical detection engineering and SOC investigation capabilities through documented, testable, and maintainable security detections.

