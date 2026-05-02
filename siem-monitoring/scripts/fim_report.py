#!/usr/bin/env python3
"""
wazuh_alert_parser.py
Ayowale Ogunnola — SOC Homelab Project
Parses Wazuh alerts across all event types:
- File Integrity Monitoring (FIM)
- Authentication failures / brute force
- Log clearing / defense evasion
- Lateral movement (SSH)
- Agent tampering
"""

import json
import sys
from datetime import datetime
from collections import defaultdict


# ── MITRE tactic labels for display ──────────────────────────
MITRE_LABELS = {
    "T1070":     "Defense Evasion — Indicator Removal",
    "T1070.004": "Defense Evasion — File Deletion",
    "T1485":     "Impact — Data Destruction",
    "T1531":     "Impact — Account Access Removal",
    "T1562.001": "Defense Evasion — Disable or Modify Tools",
    "T1565.001": "Impact — Stored Data Manipulation",
    "T1078":     "Initial Access — Valid Accounts",
    "T1021":     "Lateral Movement — Remote Services",
    "T1548.003": "Privilege Escalation — Sudo",
    "T1484":     "Privilege Escalation — Domain Policy Modification",
}

# ── Suspicious filenames worth flagging ──────────────────────
SUSPICIOUS_NAMES = [
    "svchost32", "passwords", "backup", "hosts_backup",
    ".exe", ".bat", ".ps1", "invoice", "credentials"
]

HIGH_RISK_PATHS = [
    "startup", "system32", "windows\\temp",
    "appdata\\roaming", "drivers\\etc"
]

# ── Rule IDs grouped by threat category ──────────────────────
BRUTE_FORCE_RULES  = {"60122", "5710", "5712"}
LOG_CLEAR_RULES    = {"63104", "18145"}
LATERAL_MOV_RULES  = {"5715", "5716"}
AGENT_TAMPER_RULES = {"506",  "503"}
FIM_RULES          = {"550",  "553", "554"}
PRIV_ESC_RULES     = {"5402", "67028"}


def get_mitre(alert):
    ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
    return [MITRE_LABELS.get(i, i) for i in ids] if ids else []


def is_suspicious_file(path):
    p = path.lower()
    return any(s in p for s in SUSPICIOUS_NAMES)


def is_high_risk_path(path):
    p = path.lower()
    return any(r in p for r in HIGH_RISK_PATHS)


def categorize(rule_id):
    if rule_id in BRUTE_FORCE_RULES:  return "brute_force"
    if rule_id in LOG_CLEAR_RULES:    return "log_clearing"
    if rule_id in LATERAL_MOV_RULES:  return "lateral_movement"
    if rule_id in AGENT_TAMPER_RULES: return "agent_tampering"
    if rule_id in FIM_RULES:          return "fim"
    if rule_id in PRIV_ESC_RULES:     return "privilege_escalation"
    return "other"


def parse_alerts(filepath):
    categories   = defaultdict(list)
    level_counts = defaultdict(int)
    agents       = set()

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
            mitre      = get_mitre(alert)

            agents.add(agent_name)
            level_counts[level] += 1
            cat = categorize(rule_id)

            record = {
                "timestamp" : timestamp,
                "agent"     : agent_name,
                "rule_id"   : rule_id,
                "level"     : level,
                "desc"      : desc,
                "mitre"     : mitre,
                "path"      : syscheck.get("path", ""),
                "event"     : syscheck.get("event", ""),
                "md5_before": syscheck.get("md5_before", ""),
                "md5_after" : syscheck.get("md5_after", ""),
                "full_log"  : alert.get("full_log", ""),
            }

            categories[cat].append(record)

    return categories, level_counts, agents


def print_section(title, items, show_fields):
    if not items:
        return
    print(f"\n  {'─'*55}")
    print(f"  [{len(items)}] {title}")
    print(f"  {'─'*55}")
    for item in items:
        for field in show_fields:
            val = item.get(field, "")
            if val:
                print(f"  {field:<12}: {val}")
        if item.get("mitre"):
            for m in item["mitre"]:
                print(f"  {'mitre':<12}: {m}")
        if item.get("md5_after") and item.get("md5_before") \
                and item["md5_before"] != item["md5_after"]:
            print(f"  {'md5_before':<12}: {item['md5_before']}")
            print(f"  {'md5_after':<12}: {item['md5_after']}")
            print(f"  {'virustotal':<12}: "
                  f"https://virustotal.com/gui/file/{item['md5_after']}")
        if is_suspicious_file(item.get("path", "")):
            print(f"  {'⚠ FLAG':<12}: suspicious filename detected")
        print()


def print_report(categories, level_counts, agents):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = sum(len(v) for v in categories.values())

    print(f"\n{'='*60}")
    print(f"  WAZUH ALERT REPORT — {now}")
    print(f"  Analyst : Ayowale Ogunnola")
    print(f"  Agents  : {', '.join(agents)}")
    print(f"  Total   : {total} events parsed")
    print(f"{'='*60}")

    print(f"\n  SEVERITY BREAKDOWN:")
    for lvl in sorted(level_counts.keys(), reverse=True):
        bar   = "█" * min(level_counts[lvl], 25)
        label = ("CRITICAL" if lvl >= 13 else
                 "HIGH"     if lvl >= 10 else
                 "MEDIUM"   if lvl >= 7  else
                 "LOW"      if lvl >= 4  else "INFO")
        print(f"    Level {lvl:>2} [{label:<8}] {bar} {level_counts[lvl]}")

    print(f"\n  EVENT CATEGORIES:")
    for cat, items in sorted(categories.items(), key=lambda x: -len(x[1])):
        print(f"    {cat:<25} {len(items)} events")

    # ── Brute Force ──────────────────────────────────────────
    print_section(
        "BRUTE FORCE / AUTH FAILURES",
        categories.get("brute_force", []),
        ["timestamp", "agent", "rule_id", "level", "desc", "full_log"]
    )

    # ── Log Clearing ─────────────────────────────────────────
    print_section(
        "LOG CLEARING — DEFENSE EVASION",
        categories.get("log_clearing", []),
        ["timestamp", "agent", "rule_id", "level", "desc"]
    )

    # ── Lateral Movement ─────────────────────────────────────
    print_section(
        "LATERAL MOVEMENT (SSH)",
        categories.get("lateral_movement", []),
        ["timestamp", "agent", "rule_id", "level", "desc", "full_log"]
    )

    # ── Agent Tampering ──────────────────────────────────────
    print_section(
        "AGENT STOP/START — POSSIBLE TAMPERING",
        categories.get("agent_tampering", []),
        ["timestamp", "agent", "rule_id", "level", "desc"]
    )

    # ── Privilege Escalation ─────────────────────────────────
    print_section(
        "PRIVILEGE ESCALATION (SUDO)",
        categories.get("privilege_escalation", []),
        ["timestamp", "agent", "rule_id", "level", "desc"]
    )

    # ── FIM Events ───────────────────────────────────────────
    print_section(
        "FILE INTEGRITY MONITORING",
        categories.get("fim", []),
        ["timestamp", "agent", "rule_id", "level", "desc", "path", "event"]
    )

    print(f"\n{'='*60}")
    print(f"  END OF REPORT")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "fim_alerts_sample.json"
    categories, level_counts, agents = parse_alerts(filepath)
    print_report(categories, level_counts, agents)
