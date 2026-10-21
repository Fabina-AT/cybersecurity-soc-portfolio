Endpoint Detection
1. Overview

This section contains SIEM detection use cases focused on identifying suspicious endpoint activity, malware execution, credential theft, persistence, and defense evasion.

These detections help SOC analysts investigate potentially compromised systems and identify malicious behavior on Windows endpoints.

2. Detection Objectives

The detections focus on identifying:

Suspicious process creation
Malicious PowerShell activity
Credential dumping
LOLBin abuse
Office applications spawning command interpreters
Suspicious scheduled task creation
Unauthorized service creation
Suspicious WMI execution
Ransomware-like file modifications
Defense evasion and security control tampering
3. Data Sources

Endpoint detections may use logs and telemetry from:

Windows Security Events
Sysmon
Microsoft Defender for Endpoint
Windows PowerShell logs
Windows Task Scheduler logs
Windows service logs
Endpoint Detection and Response (EDR) platforms
File and process monitoring tools

Common Windows event examples include:

Event ID 4688: Process creation
Event ID 4697: Service installation auditing
Event ID 7045: New service installation
Sysmon Event ID 1: Process creation
Sysmon Event ID 3: Network connection

Event availability depends on the operating system, audit configuration, and log collection setup.

4. Key Endpoint Fields
Field	Description
Timestamp	Time the activity occurred
Hostname	Affected endpoint
Username	Account associated with the activity
Process Name	Executed process
Command Line	Arguments used to launch the process
Parent Process	Process that started the activity
Process ID	Identifier of the process
File Hash	File identifier, where available
Destination IP	Remote IP associated with network activity
Event ID	Identifier of the recorded event

Available fields depend on the data source.

5. Detection Use Cases
Detection	File
Defense Evasion	Defense Evasion.md
LOLBin Execution Detection	LOLBin Execution Detection.md
LSASS Credential Dumping Detection	LSASS-Credential Dumping Detection.md
Office Application Spawning Command Interpreter	Office Application Spawning Command Interpreter.md
Ransomware Mass File Modification Detection	Ransomware Mass File Modification Detection.md
Suspicious Process Creation	Suspicious Process Creation.md
Suspicious Scheduled Task Creation	Suspicious Scheduled Task Creation Detection.md
Suspicious Service Creation	Suspicious Service Creation Detection.md
Suspicious WMI Execution	Suspicious WMI Execution Detection.md
Suspicious PowerShell	suspicious-powershell.md
6. Investigation

When an endpoint alert triggers, the SOC analyst should review:

Affected host and user
Process name and command line
Parent-child process relationships
Executable location and file hash
Process execution time
Network connections
Related authentication activity
Persistence mechanisms
Other endpoint alerts
Threat intelligence and file reputation

Correlate endpoint activity with identity, DNS, and network logs where available.

7. False Positives and Tuning

Potential false positives include:

Legitimate administrative scripts
Software installations and updates
Approved PowerShell automation
Endpoint management tools
Scheduled maintenance tasks
Authorized security testing

Improve detection accuracy through process ancestry analysis, command-line inspection, approved software lists, host baselines, and documented exceptions.

Avoid excluding entire tools or process names when attackers may abuse legitimate software.

8. Response

When malicious endpoint activity is suspected:

Validate the alert and identify the affected host.
Review the process tree and command line.
Investigate associated files and network connections.
Check for credential theft and persistence.
Isolate the endpoint when justified and authorized.
Contain affected accounts if compromise is suspected.
Preserve evidence and escalate according to incident-response procedures.
9. MITRE ATT&CK

Relevant techniques include:

T1059 – Command and Scripting Interpreter
T1055 – Process Injection
T1003 – OS Credential Dumping
T1053 – Scheduled Task/Job
T1562 – Impair Defenses

Map each detection to the techniques that match its actual detection logic.

10. Validation

Each detection should be tested in an authorized lab environment to confirm:

Required endpoint logs are available.
The query executes successfully.
Expected activity triggers the detection.
Benign administrative activity is evaluated.
Alert details support investigation.
False positives and limitations are documented.

Status: Detection use cases are documented and should be marked validated only after successful testing.

11. References
Microsoft Sentinel
Microsoft Defender for Endpoint
Sysmon Documentation
MITRE ATT&CK
