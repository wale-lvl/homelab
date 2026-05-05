#!/usr/bin/env python3
"""
ir_triage.py
Ayowale Ogunnola — SOC Homelab Project
Automated first-response triage script.
Ingests Wazuh alert JSON and produces a structured IR summary
with timeline, threat classification, and recommended actions.
"""

import json
import sys
from datetime import datetime
from collections import defaultdict


# ── Threat classification thresholds ─────────────────────────
CRITICAL_RULES = {"63104", "553"}   # log clearing, file deletion
HIGH_RULES     = {"60122", "554", "550"}  # brute force, FIM
LATERAL_RULES  = {"5715", "5716"}   # SSH movement

# ── Response playbooks per threat type ───────────────────────
PLAYBOOKS = {
    "brute_force": [
        "1. Verify if targeted account exists in Active Directory",
        "2. Check if any login eventually succeeded after failures",
        "3. Block source IP at the firewall if external",
        "4. Reset password for targeted account",
        "5. Enable account lockout policy if not already set",
        "6. Escalate to Tier 2 if more than 10 attempts detected",
    ],
    "log_clearing": [
        "1. IMMEDIATELY preserve all remaining logs to external storage",
        "2. Identify which process cleared the log (check Event ID 1102)",
        "3. Correlate with other events 5 minutes before clearing",
        "4. Assume breach — treat as active incident",
        "5. Isolate endpoint from network pending investigation",
        "6. Escalate to Tier 2 and notify incident response team",
    ],
    "fim_suspicious": [
        "1. Calculate MD5/SHA256 hash of flagged file",
        "2. Submit hash to VirusTotal for reputation check",
        "3. Check file creation time against user login events",
        "4. Determine if file was executed (check Sysmon Event ID 1)",
        "5. If executable — isolate endpoint immediately",
        "6. Preserve file as forensic evidence before deletion",
    ],
    "lateral_movement": [
        "1. Identify source and destination of SSH connection",
        "2. Verify if connection was authorized",
        "3. Check what commands were run in the SSH session",
        "4. Review authentication logs for same source IP",
        "5. If unauthorized — revoke SSH keys and reset credentials",
        "6. Audit all systems the source IP has connected to",
    ],
    "privilege_escalation": [
        "1. Identify which account performed the escalation",
        "2. Verify if sudo usage was expected for that account",
        "3. Review commands executed with elevated privileges",
        "4. Check if new accounts or SSH keys were created",
        "5. Review /etc/sudoers for unauthorized modifications",
        "6. Escalate if escalation was by a service account",
    ],
}


def classify_alert(rule_id):
    if rule_id in CRITICAL_RULES:
        return "log_clearing" if rule_id == "63104" else "fim_suspicious"
    if rule_id in HIGH_RULES:
        return "brute_force" if rule_id == "60122" else "fim_suspicious"
    if rule_id in LATERAL_RULES:
        return "lateral_movement"
    if rule_id in {"5402", "67028"}:
        return "privilege_escalation"
    return None


def parse_alerts(filepath):
    timeline        = []
    threat_types    = defaultdict(list)
    agents          = set()
    max_level       = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            rule       = alert.get("rule", {})
            rule_id    = str(rule.get("id", ""))
            level      = rule.get("level", 0)
            desc       = rule.get("description", "unknown")
            timestamp  = alert.get("timestamp", "")
            agent_name = alert.get("agent", {}).get("name", "unknown")
            syscheck   = alert.get("syscheck", {})
            mitre      = alert.get("rule", {}).get("mitre", {})

            agents.add(agent_name)
            max_level = max(max_level, level)

            record = {
                "timestamp" : timestamp,
                "agent"     : agent_name,
                "rule_id"   : rule_id,
                "level"     : level,
                "desc"      : desc,
                "path"      : syscheck.get("path", ""),
                "md5"       : syscheck.get("md5_after", ""),
                "mitre_id"  : mitre.get("id", []),
                "mitre_tac" : mitre.get("tactic", []),
            }

            timeline.append(record)
            threat_type = classify_alert(rule_id)
            if threat_type:
                threat_types[threat_type].append(record)

    timeline.sort(key=lambda x: x["timestamp"])
    return timeline, threat_types, agents, max_level


def severity_rating(max_level, threat_types):
    if "log_clearing" in threat_types:
        return "CRITICAL"
    if max_level >= 10:
        return "HIGH"
    if max_level >= 7 or "brute_force" in threat_types:
        return "MEDIUM"
    return "LOW"


def print_report(timeline, threat_types, agents, max_level, filepath):
    now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = severity_rating(max_level, threat_types)
    inc_id   = f"INC-{datetime.now().strftime('%Y%m%d')}-001"

    print(f"\n{'='*60}")
    print(f"  INCIDENT RESPONSE TRIAGE REPORT")
    print(f"  Incident ID : {inc_id}")
    print(f"  Generated   : {now}")
    print(f"  Analyst     : Ayowale Ogunnola")
    print(f"  Severity    : {severity}")
    print(f"  Source file : {filepath}")
    print(f"{'='*60}")

    print(f"\n  AFFECTED SYSTEMS:")
    for agent in agents:
        print(f"    - {agent}")

    print(f"\n  THREAT SUMMARY:")
    print(f"    Total events analysed : {len(timeline)}")
    print(f"    Highest alert level   : {max_level}")
    print(f"    Threat categories     : {len(threat_types)}")
    for t, events in threat_types.items():
        print(f"      - {t.replace('_',' ').title():<30} {len(events)} events")

    print(f"\n  ATTACK TIMELINE (key events only):")
    print(f"  {'─'*55}")
    for event in timeline:
        if classify_alert(event["rule_id"]):
            mitre = ", ".join(event["mitre_tac"]) if event["mitre_tac"] else "N/A"
            print(f"  [{event['timestamp'][:19]}] Level {event['level']:<2} | {event['desc']}")
            if event["path"]:
                print(f"    Path  : {event['path']}")
            if event["md5"]:
                print(f"    MD5   : {event['md5']}")
                print(f"    VT    : https://virustotal.com/gui/file/{event['md5']}")
            print(f"    MITRE : {mitre}")
            print()

    print(f"\n  RECOMMENDED RESPONSE ACTIONS:")
    print(f"  {'─'*55}")
    for threat_type, events in threat_types.items():
        print(f"\n  [{threat_type.replace('_',' ').upper()}]")
        steps = PLAYBOOKS.get(threat_type, ["No playbook defined for this threat type."])
        for step in steps:
            print(f"    {step}")

    print(f"\n{'='*60}")
    print(f"  END OF TRIAGE REPORT — {inc_id}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "alerts.json"
    timeline, threat_types, agents, max_level = parse_alerts(filepath)
    print_report(timeline, threat_types, agents, max_level, filepath)
