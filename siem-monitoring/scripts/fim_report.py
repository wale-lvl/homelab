#!/usr/bin/env python3
"""
fim_report.py
Ayowale Ogunnola — SOC Homelab Project
Parses Wazuh FIM alerts and produces a ranked threat summary.
"""

import json
import sys
from datetime import datetime
from collections import defaultdict


SEVERITY_LABELS = {
    range(1, 4):  "informational",
    range(4, 7):  "low",
    range(7, 10): "medium",
    range(10, 13):"high",
    range(13, 16):"critical"
}

HIGH_RISK_PATHS = [
    "startup",
    "system32",
    "windows\\temp",
    "appdata\\roaming",
    "drivers\\etc"
]


def get_severity_label(level):
    for r, label in SEVERITY_LABELS.items():
        if level in r:
            return label
    return "unknown"


def is_high_risk_path(path):
    path_lower = path.lower()
    return any(p in path_lower for p in HIGH_RISK_PATHS)


def parse_fim_alerts(filepath):
    events      = []
    path_counts = defaultdict(int)
    event_types = defaultdict(int)
    high_risk   = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "syscheck" not in alert:
                continue

            syscheck   = alert["syscheck"]
            rule       = alert.get("rule", {})
            agent      = alert.get("agent", {})

            path       = syscheck.get("path", "unknown")
            event_type = syscheck.get("event", "unknown")
            level      = rule.get("level", 0)
            rule_id    = rule.get("id", "unknown")
            desc       = rule.get("description", "unknown")
            timestamp  = alert.get("timestamp", "")
            md5_after  = syscheck.get("md5_after", None)
            agent_name = agent.get("name", "unknown")

            record = {
                "timestamp" : timestamp,
                "agent"     : agent_name,
                "path"      : path,
                "event"     : event_type,
                "level"     : level,
                "severity"  : get_severity_label(level),
                "rule_id"   : rule_id,
                "rule_desc" : desc,
                "md5"       : md5_after,
                "high_risk" : is_high_risk_path(path)
            }

            events.append(record)
            path_counts[path] += 1
            event_types[event_type] += 1

            if is_high_risk_path(path):
                high_risk.append(record)

    return events, path_counts, event_types, high_risk


def print_report(events, path_counts, event_types, high_risk):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*60}")
    print(f"  FIM ALERT REPORT — Generated {now}")
    print(f"  Analyst: Ayowale Ogunnola")
    print(f"{'='*60}")
    print(f"\n  Total FIM events    : {len(events)}")
    print(f"  High-risk path hits : {len(high_risk)}")

    print(f"\n  Event breakdown:")
    for etype, count in sorted(event_types.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 30)
        print(f"    {etype:<12} {bar} {count}")

    print(f"\n  Most active paths:")
    top_paths = sorted(path_counts.items(), key=lambda x: -x[1])[:5]
    for path, count in top_paths:
        print(f"    [{count}x]  {path}")

    if high_risk:
        print(f"\n  [!] HIGH-RISK PATH EVENTS ({len(high_risk)} total):")
        print(f"  {'─'*55}")
        for evt in high_risk:
            print(f"  Time     : {evt['timestamp']}")
            print(f"  Agent    : {evt['agent']}")
            print(f"  Path     : {evt['path']}")
            print(f"  Action   : {evt['event'].upper()}")
            print(f"  Severity : {evt['severity']} (level {evt['level']})")
            if evt["md5"]:
                print(f"  MD5      : {evt['md5']}")
                print(f"  VT Check : https://virustotal.com/gui/file/{evt['md5']}")
            print(f"  {'─'*55}")
    else:
        print("\n  No high-risk path events detected.")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "fim_alerts_sample.json"
    events, path_counts, event_types, high_risk = parse_fim_alerts(filepath)
    print_report(events, path_counts, event_types, high_risk)
