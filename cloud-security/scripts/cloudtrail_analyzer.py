#!/usr/bin/env python3
"""
cloudtrail_analyzer.py
Ayowale Ogunnola — SOC Homelab Project
Pulls and analyzes AWS CloudTrail events, flagging suspicious
cloud activity including root logins, MFA failures, and IAM changes.
"""

import boto3
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict


# High-risk API calls worth flagging
SUSPICIOUS_EVENTS = {
    "ConsoleLogin"              : "Console login detected",
    "CreateUser"                : "New IAM user created",
    "CreateAccessKey"           : "New access key created",
    "DeleteTrail"               : "CloudTrail trail deleted",
    "StopLogging"               : "CloudTrail logging stopped",
    "PutBucketPolicy"           : "S3 bucket policy modified",
    "AuthorizeSecurityGroup"    : "Security group rule added",
    "DeleteSecurityGroup"       : "Security group deleted",
    "AttachUserPolicy"          : "Policy attached to user",
    "CreateLoginProfile"        : "Console password created for user",
    "UpdateLoginProfile"        : "Console password updated",
    "DeleteLogGroup"            : "CloudWatch log group deleted",
}

REGION = "eu-north-1"


def get_events(hours=24):
    client    = boto3.client("cloudtrail", region_name=REGION)
    end_time  = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    events    = []
    paginator = client.get_paginator("lookup_events")

    pages = paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"MaxItems": 200}
    )

    for page in pages:
        events.extend(page.get("Events", []))

    return events


def analyze_events(events):
    flagged        = []
    root_events    = []
    no_mfa_events  = []
    denied_events  = []
    user_counts    = defaultdict(int)
    event_counts   = defaultdict(int)

    for event in events:
        raw        = json.loads(event.get("CloudTrailEvent", "{}"))
        username   = event.get("Username", "unknown")
        event_name = event.get("EventName", "unknown")
        event_time = event.get("EventTime")
        source     = event.get("EventSource", "")
        readonly   = event.get("ReadOnly", "true")

        user_identity = raw.get("userIdentity", {})
        user_type     = user_identity.get("type", "")
        mfa_auth      = user_identity.get("sessionContext", {}) \
                            .get("attributes", {}) \
                            .get("mfaAuthenticated", "true")
        error_code    = raw.get("errorCode", "")

        user_counts[username] += 1
        event_counts[event_name] += 1

        record = {
            "time"       : str(event_time),
            "user"       : username,
            "user_type"  : user_type,
            "event"      : event_name,
            "source"     : source,
            "readonly"   : readonly,
            "mfa"        : mfa_auth,
            "error"      : error_code,
            "region"     : raw.get("awsRegion", ""),
            "source_ip"  : raw.get("sourceIPAddress", ""),
        }

        # Root account usage
        if user_type == "Root":
            root_events.append(record)

        # No MFA on console login
        if mfa_auth == "false" and event_name == "ConsoleLogin":
            no_mfa_events.append(record)

        # Access denied events
        if error_code in ("AccessDenied", "Client.UnauthorizedOperation"):
            denied_events.append(record)

        # Suspicious API calls
        if event_name in SUSPICIOUS_EVENTS:
            record["flag"] = SUSPICIOUS_EVENTS[event_name]
            flagged.append(record)

    return flagged, root_events, no_mfa_events, \
           denied_events, user_counts, event_counts


def print_report(flagged, root_events, no_mfa_events,
                 denied_events, user_counts, event_counts, hours):

    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total  = sum(event_counts.values())

    print(f"\n{'='*60}")
    print(f"  AWS CLOUDTRAIL SECURITY REPORT")
    print(f"  Generated : {now}")
    print(f"  Analyst   : Ayowale Ogunnola")
    print(f"  Region    : {REGION}")
    print(f"  Window    : Last {hours} hours")
    print(f"{'='*60}")

    print(f"\n  SUMMARY:")
    print(f"    Total events analysed : {total}")
    print(f"    Root account events   : {len(root_events)}")
    print(f"    No-MFA console logins : {len(no_mfa_events)}")
    print(f"    Access denied errors  : {len(denied_events)}")
    print(f"    Suspicious API calls  : {len(flagged)}")

    print(f"\n  TOP API CALLERS:")
    for user, count in sorted(user_counts.items(),
                               key=lambda x: -x[1])[:5]:
        bar = "█" * min(count, 25)
        print(f"    {user:<25} {bar} {count}")

    print(f"\n  TOP EVENT TYPES:")
    for event, count in sorted(event_counts.items(),
                                key=lambda x: -x[1])[:8]:
        print(f"    {event:<40} {count}")

    if root_events:
        print(f"\n  [!] ROOT ACCOUNT ACTIVITY ({len(root_events)} events):")
        print(f"  {'─'*55}")
        for e in root_events:
            print(f"  Time     : {e['time']}")
            print(f"  Event    : {e['event']}")
            print(f"  Source   : {e['source']}")
            print(f"  IP       : {e['source_ip']}")
            print(f"  MFA      : {e['mfa']}")
            if e['mfa'] == 'false':
                print(f"  ⚠ CRITICAL: Root login without MFA")
            print()

    if no_mfa_events:
        print(f"\n  [!] CONSOLE LOGINS WITHOUT MFA:")
        print(f"  {'─'*55}")
        for e in no_mfa_events:
            print(f"  Time  : {e['time']}")
            print(f"  User  : {e['user']}")
            print(f"  IP    : {e['source_ip']}")
            print()

    if denied_events:
        print(f"\n  [!] ACCESS DENIED EVENTS ({len(denied_events)} total):")
        print(f"  {'─'*55}")
        for e in denied_events[:5]:
            print(f"  Time  : {e['time']}")
            print(f"  User  : {e['user']}")
            print(f"  Event : {e['event']}")
            print(f"  IP    : {e['source_ip']}")
            print()

    if flagged:
        print(f"\n  [!] SUSPICIOUS API CALLS:")
        print(f"  {'─'*55}")
        for e in flagged:
            print(f"  Time  : {e['time']}")
            print(f"  User  : {e['user']}")
            print(f"  Event : {e['event']}")
            print(f"  Flag  : {e['flag']}")
            print()

    print(f"\n  RECOMMENDED ACTIONS:")
    if root_events:
        print(f"  - Enable MFA on root account immediately")
        print(f"  - Create IAM admin user for daily operations")
        print(f"  - Lock root account access keys if any exist")
    if denied_events:
        print(f"  - Review IAM policies for soc-analyst user")
        print(f"  - Investigate source of unauthorized API calls")
    if no_mfa_events:
        print(f"  - Enforce MFA policy across all IAM users")

    print(f"\n{'='*60}")
    print(f"  END OF REPORT")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    import sys
    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    print(f"  Fetching CloudTrail events for last {hours} hours...")
    events = get_events(hours)
    flagged, root_events, no_mfa_events, \
    denied_events, user_counts, event_counts = analyze_events(events)
    print_report(flagged, root_events, no_mfa_events,
                 denied_events, user_counts, event_counts, hours)
