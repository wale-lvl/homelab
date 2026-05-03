#!/usr/bin/env python3
"""
pcap_analyzer.py
Ayowale Ogunnola — SOC Homelab Project
Analyzes PCAP files using tshark and flags suspicious network activity.
"""

import subprocess
import json
import sys
from collections import defaultdict
from datetime import datetime


SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite backdoor",
    8080: "Alternate HTTP",
    9001: "Tor default",
}

SUSPICIOUS_KEYWORDS = [
    "cmd.exe", "powershell", "wget", "curl",
    "passwd", "shadow", "/etc/", "base64"
]


def run_tshark(pcap_file, fields, display_filter=""):
    cmd = ["tshark", "-r", pcap_file, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=|"]
    if display_filter:
        cmd += ["-Y", display_filter]
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    return lines


def parse_connections(pcap_file):
    fields = ["ip.src", "ip.dst", "tcp.dstport", "udp.dstport",
              "frame.time_relative", "_ws.col.Protocol"]
    lines = run_tshark(pcap_file, fields)

    connections = []
    ip_counts   = defaultdict(int)
    port_counts = defaultdict(int)
    suspicious  = []

    for line in lines:
        parts = line.split("|")
        if len(parts) < 6:
            continue

        src, dst, tcp_port, udp_port, time, proto = parts
        port = tcp_port or udp_port

        ip_counts[src] += 1
        if port:
            try:
                port_counts[int(port)] += 1
            except ValueError:
                pass

        record = {
            "src"   : src,
            "dst"   : dst,
            "port"  : port,
            "proto" : proto,
            "time"  : time,
        }
        connections.append(record)

        if port:
            try:
                p = int(port)
                if p in SUSPICIOUS_PORTS:
                    record["flag"] = SUSPICIOUS_PORTS[p]
                    suspicious.append(record)
            except ValueError:
                pass

    return connections, ip_counts, port_counts, suspicious


def parse_http(pcap_file):
    fields = ["ip.src", "ip.dst", "http.request.method",
              "http.request.uri", "http.host"]
    lines  = run_tshark(pcap_file, fields, "http.request")

    requests       = []
    flagged        = []

    for line in lines:
        parts = line.split("|")
        if len(parts) < 5:
            continue
        src, dst, method, uri, host = parts
        record = {
            "src"    : src,
            "dst"    : dst,
            "method" : method,
            "uri"    : uri,
            "host"   : host,
        }
        requests.append(record)
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in uri.lower():
                record["flag"] = f"suspicious keyword: {kw}"
                flagged.append(record)
                break

    return requests, flagged


def parse_dns(pcap_file):
    fields = ["ip.src", "dns.qry.name", "dns.resp.name"]
    lines  = run_tshark(pcap_file, fields, "dns")

    queries    = []
    long_domains = []

    for line in lines:
        parts = line.split("|")
        if len(parts) < 2:
            continue
        src   = parts[0]
        query = parts[1] if len(parts) > 1 else ""
        record = {"src": src, "query": query}
        queries.append(record)
        if len(query) > 50:
            record["flag"] = "unusually long domain (possible DNS tunneling)"
            long_domains.append(record)

    return queries, long_domains


def print_report(connections, ip_counts, port_counts,
                 suspicious_conns, http_requests, flagged_http,
                 dns_queries, flagged_dns, pcap_file):

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*60}")
    print(f"  PCAP ANALYSIS REPORT — {now}")
    print(f"  Analyst : Ayowale Ogunnola")
    print(f"  File    : {pcap_file}")
    print(f"{'='*60}")

    print(f"\n  SUMMARY:")
    print(f"    Total packets      : {len(connections)}")
    print(f"    Unique source IPs  : {len(ip_counts)}")
    print(f"    HTTP requests      : {len(http_requests)}")
    print(f"    DNS queries        : {len(dns_queries)}")
    print(f"    Suspicious conns   : {len(suspicious_conns)}")
    print(f"    Flagged HTTP       : {len(flagged_http)}")
    print(f"    Flagged DNS        : {len(flagged_dns)}")

    print(f"\n  TOP TALKERS (most active IPs):")
    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:5]
    for ip, count in top_ips:
        bar = "█" * min(count, 30)
        print(f"    {ip:<20} {bar} {count}")

    print(f"\n  TOP DESTINATION PORTS:")
    top_ports = sorted(port_counts.items(), key=lambda x: -x[1])[:5]
    for port, count in top_ports:
        label = SUSPICIOUS_PORTS.get(port, "")
        flag  = " *** SUSPICIOUS ***" if label else ""
        print(f"    Port {port:<6} {count} packets  {label}{flag}")

    if http_requests:
        print(f"\n  HTTP REQUESTS ({len(http_requests)} total):")
        print(f"  {'─'*55}")
        for r in http_requests[:10]:
            print(f"  {r['method']:<6} {r['host']}{r['uri']}")
            if "flag" in r:
                print(f"  ⚠ FLAG: {r['flag']}")

    if flagged_dns:
        print(f"\n  FLAGGED DNS QUERIES:")
        print(f"  {'─'*55}")
        for d in flagged_dns:
            print(f"  {d['src']:<20} {d['query']}")
            print(f"  ⚠ FLAG: {d['flag']}")

    if suspicious_conns:
        print(f"\n  SUSPICIOUS CONNECTIONS:")
        print(f"  {'─'*55}")
        for c in suspicious_conns:
            print(f"  {c['src']} -> {c['dst']}:{c['port']}")
            print(f"  ⚠ FLAG: {c['flag']}")

    print(f"\n{'='*60}")
    print(f"  END OF REPORT")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    import shutil, os
    pcap = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
    tmp  = f"/tmp/{os.path.basename(pcap)}"
    shutil.copy2(pcap, tmp)
    os.chmod(tmp, 0o644)

    connections, ip_counts, port_counts, suspicious_conns = \
        parse_connections(tmp)
    http_requests, flagged_http = parse_http(tmp)
    dns_queries,   flagged_dns  = parse_dns(tmp)

    print_report(connections, ip_counts, port_counts,
                 suspicious_conns, http_requests, flagged_http,
                 dns_queries, flagged_dns, pcap)
