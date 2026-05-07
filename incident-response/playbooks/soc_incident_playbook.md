# SOC Incident Response Playbook
**Author:** Ayowale Ogunnola  
**Version:** 1.0  
**Last Updated:** May 2026

This playbook defines structured response procedures for the most
common alert types detected in a Wazuh SIEM environment. Each
scenario includes detection criteria, investigation steps, and
containment actions.

---

## Playbook 1 — Brute Force / Authentication Failures

**Detection:** Multiple failed login attempts against a single account  
**Wazuh Rule:** 60122 | **Severity:** Level 5 | **MITRE:** T1110

### Investigation Steps
1. Identify the targeted username and source IP from alert data
2. Determine if the account exists in Active Directory
3. Check if any login attempt eventually succeeded after failures
4. Calculate the time window between first and last attempt
5. Determine if source IP is internal or external

### Containment Actions
- If external IP: block at perimeter firewall immediately
- If more than 10 attempts: lock the targeted account
- If a successful login followed failures: assume compromise
- Reset credentials for targeted account
- Enable account lockout policy if not configured
- Escalate to Tier 2 if successful login is confirmed

### Evidence to Collect
- Source IP address and geolocation
- Targeted username
- Timestamps of all attempts
- Windows Event ID 4625 logs

---

## Playbook 2 — Log Clearing / Defense Evasion

**Detection:** Windows event log cleared  
**Wazuh Rule:** 63104 | **Severity:** Level 5 | **MITRE:** T1070

### Investigation Steps
1. Identify which log was cleared and at what time
2. Check Windows Event ID 1102 for the account that cleared it
3. Correlate with all other events in the 10 minutes before clearing
4. Determine if any brute force or lateral movement preceded it
5. Check if this is a scheduled maintenance task or unauthorized

### Containment Actions
- IMMEDIATELY preserve all remaining logs to external storage
- Treat as active breach until proven otherwise
- Isolate the affected endpoint from the network
- Notify Tier 2 and incident response team
- Preserve memory dump before any remediation

### Evidence to Collect
- Event ID 1102 — who cleared the log
- Timeline of events preceding the clearing
- Full system image if breach is confirmed

---

## Playbook 3 — File Integrity Violation (FIM)

**Detection:** Unauthorized file creation, modification, or deletion  
**Wazuh Rules:** 550, 553, 554 | **Severity:** Level 5-7 | **MITRE:** T1565.001

### Investigation Steps
1. Note the full file path and filename
2. Extract MD5/SHA256 hash from Wazuh alert
3. Submit hash to VirusTotal for reputation check
4. Cross-reference file creation time with user login events
5. Determine if the file was executed using Sysmon Event ID 1
6. Flag executables in non-standard paths as high priority

### Containment Actions
- If .exe or .bat in temp/startup folder: isolate endpoint immediately
- Preserve the file as forensic evidence before deleting
- If hash is malicious on VirusTotal: escalate to Tier 2
- Remove file and scan for persistence mechanisms
- Review startup folders and scheduled tasks for persistence

### Evidence to Collect
- Full file path
- MD5, SHA1, SHA256 hashes
- File creation timestamp
- User account active at time of creation
- VirusTotal report

---

## Playbook 4 — Lateral Movement (SSH)

**Detection:** Successful SSH authentication between internal systems  
**Wazuh Rule:** 5715 | **Severity:** Level 3 | **MITRE:** T1021

### Investigation Steps
1. Identify source IP and destination of SSH connection
2. Verify if the connection was authorized and expected
3. Review commands executed during the SSH session
4. Check if the same source IP appears in other alert types
5. Determine if SSH keys or new accounts were created post-connection

### Containment Actions
- If unauthorized: revoke SSH keys for the involved account
- Reset credentials on both source and destination systems
- Review authorized_keys file for unauthorized entries
- Audit all systems the source IP has connected to
- Block source IP if connection was external

### Evidence to Collect
- Source and destination IPs and hostnames
- Timestamp and duration of session
- Commands executed (if available via audit logs)
- SSH key fingerprints used

---

## Playbook 5 — Privilege Escalation

**Detection:** Sudo execution or special privileges assigned to logon  
**Wazuh Rules:** 5402, 67028 | **Severity:** Level 3 | **MITRE:** T1548.003

### Investigation Steps
1. Identify which account performed the privilege escalation
2. Verify if sudo usage was expected for that account and time
3. Review the exact command executed with elevated privileges
4. Check if new user accounts or SSH keys were created
5. Review /etc/sudoers for unauthorized modifications

### Containment Actions
- If unexpected: suspend the account pending investigation
- Revoke elevated privileges if not required for role
- Review all actions taken during the elevated session
- Escalate if escalation was performed by a service account
- Audit cron jobs and startup scripts for persistence

### Evidence to Collect
- Username and UID
- Exact command run with sudo
- Timestamp
- Terminal/TTY used
- Any files created or modified during session

---

## Severity Classification Guide

| Level | Label | Response Time | Action |
|-------|-------|--------------|--------|
| 13-15 | Critical | Immediate | Isolate, escalate, preserve |
| 10-12 | High | 15 minutes | Investigate, contain |
| 7-9 | Medium | 1 hour | Investigate, monitor |
| 4-6 | Low | 4 hours | Log, review |
| 1-3 | Info | 24 hours | Monitor only |

---

## Escalation Contacts

| Tier | Trigger |
|------|---------|
| Tier 1 | Initial triage, low and medium alerts |
| Tier 2 | High severity, confirmed compromise, log clearing |
| Incident Response Team | Critical severity, active breach, ransomware |
| Management | Data breach, regulatory notification required |
