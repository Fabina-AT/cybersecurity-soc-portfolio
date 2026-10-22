02 - Incident Response

Incident response write-ups built as lab simulations using realistic scenarios, sample log data and standard SOC tooling (Microsoft Sentinel, Defender, SentinelOne, VirusTotal, Any.Run). No real client data is used. IPs and domains are reserved or example values.



Framework

Each case follows the NIST SP 800-61 lifecycle: Preparation, Detection and Analysis, Containment, Eradication, Recovery, Lessons Learned



Case Index

Case 1: Phishing to account compromise - folder 01-Phishing-Compromise - T1566, T1078 - Done

Case 2: Brute force / password spraying to successful login - folder 03-Compromised-Account - T1110, T1078 - Done

Case 3: Malware execution on an endpoint - folder 04-Malware-Infection - T1204, T1059.001 - Done

Case 4: Ransomware triage - folder 02-Ransomware - T1486, T1490 - Planned

Case 5: Suspicious PowerShell / LOLBin execution - folder 05-Suspicious-PowerShell - T1059.001, T1218 - Planned

Case 6: Credential dumping (LSASS access) - folder 06-Credential-Dumping - T1003.001 - Planned

Case 7: Lateral movement (RDP / SMB / WinRM) - folder 07-Lateral-Movement - T1021 - Planned

Case 8: C2 beaconing / DNS tunneling - folder 08-C2-Beaconing - T1071, T1572 - Planned

Case 9: Data exfiltration / insider threat - folder 09-Data-Exfiltration - T1567, T1048 - Planned

Case 10: Azure / AWS account takeover - folder 10-Cloud-Account-Takeover - T1078.004 - Planned
Templates

See 00-IR-Templates/ for the incident report template and severity matrix used across all cases.
