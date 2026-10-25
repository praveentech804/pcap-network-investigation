#!/usr/bin/env python3
"""Lightweight, explainable analyzer for Wireshark/tshark CSV exports."""
import argparse
import csv
import ipaddress
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

def norm(value):
    value = (value or "").strip()
    return value

def first(row, *names):
    for name in names:
        value = norm(row.get(name, ""))
        if value:
            return value
    return ""

def int_value(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None

def valid_ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None

def is_private(value):
    ip = valid_ip(value)
    return bool(ip and (ip.is_private or ip.is_loopback or ip.is_link_local))

def analyze(input_csv):
    with open(input_csv, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row")
        rows = list(reader)
        fields = set(reader.fieldnames)

    # Supports common Wireshark CSV column names.
    src_keys = ("ip.src", "ipv6.src", "Source", "source", "src_ip")
    dst_keys = ("ip.dst", "ipv6.dst", "Destination", "destination", "dst_ip")
    src_port_keys = ("tcp.srcport", "udp.srcport", "Source Port", "srcport")
    dst_port_keys = ("tcp.dstport", "udp.dstport", "Destination Port", "dstport")
    time_keys = ("frame.time", "frame.time_epoch", "Time", "timestamp")
    proto_keys = ("_ws.col.Protocol", "Protocol", "ip.proto")
    dns_keys = ("dns.qry.name", "Queries", "dns_query")
    host_keys = ("http.host", "Host", "http_host")
    tls_keys = ("tls.handshake.extensions_server_name", "Server Name", "sni")
    len_keys = ("frame.len", "Length", "length")

    findings = []
    src_counts, dst_port_sets, src_dst_counts = Counter(), defaultdict(set), Counter()
    dst_counts, domain_counts, host_counts = Counter(), Counter(), Counter()
    protocol_counts = Counter()
    total_bytes = 0
    nonempty_rows = 0

    for row in rows:
        src, dst = first(row, *src_keys), first(row, *dst_keys)
        sport, dport = int_value(first(row, *src_port_keys)), int_value(first(row, *dst_port_keys))
        ts = first(row, *time_keys)
        proto = first(row, *proto_keys)
        dns, host, sni = first(row, *dns_keys), first(row, *host_keys), first(row, *tls_keys)
        length = int_value(first(row, *len_keys))
        if src or dst:
            nonempty_rows += 1
        if src:
            src_counts[src] += 1
        if dst:
            dst_counts[dst] += 1
        if src and dport is not None:
            dst_port_sets[src].add(dport)
        if src and dst:
            src_dst_counts[(src, dst)] += 1
        if proto:
            protocol_counts[proto] += 1
        if dns:
            domain_counts[dns.lower()] += 1
        if host:
            host_counts[host.lower()] += 1
        if length is not None:
            total_bytes += length

    def add(severity, rule, src="", dst="", evidence="", recommendation=""):
        findings.append({
            "severity": severity, "rule": rule, "src_ip": src, "dst_ip": dst,
            "evidence": evidence, "recommendation": recommendation
        })

    # Heuristic: a source using many distinct destination ports may indicate scanning.
    for src, ports in dst_port_sets.items():
        if len(ports) >= 25:
            add("medium", "Possible port scan", src, "",
                f"{len(ports)} distinct destination ports observed from one source",
                "Validate against the host role and time window; inspect TCP flags/flows before confirming scanning.")

    # Repeated traffic to a single destination can be noteworthy, but is not proof of an attack.
    for (src, dst), count in src_dst_counts.items():
        if count >= 500 and src != dst:
            add("low", "High-volume source/destination pair", src, dst,
                f"{count} packets/rows between this source and destination",
                "Review byte counts, flow duration, and expected application behavior.")

    # Mark a commonly abused WPAD-like lookalike for analyst review, not as confirmed malware.
    for domain, count in domain_counts.items():
        if domain == "wpad.easyas123.tech" or domain.endswith(".easyas123.tech"):
            add("high", "Unusual WPAD/custom domain observed", "", "",
                f"DNS query {domain!r} observed {count} time(s)",
                "Investigate DNS context, endpoint ownership, and proxy auto-discovery configuration; do not treat this heuristic alone as proof of compromise.")

    # Plain HTTP to an external IP can warrant review.
    for host, count in host_counts.items():
        ip = valid_ip(host.split(":")[0])
        if ip and not is_private(str(ip)):
            add("medium", "HTTP Host is a public IP address", "", host,
                f"HTTP Host value observed {count} time(s)",
                "Inspect request paths, response codes, and destination reputation using approved threat-intelligence sources.")

    # Summary metadata
    summary = {
        "input_file": os.path.basename(input_csv),
        "rows_total": len(rows),
        "rows_with_ip": nonempty_rows,
        "unique_source_ips": len(src_counts),
        "unique_destination_ips": len(dst_counts),
        "unique_dns_names": len(domain_counts),
        "unique_http_hosts": len(host_counts),
        "total_frame_bytes": total_bytes,
        "protocol_counts": dict(protocol_counts.most_common()),
        "top_source_ips": src_counts.most_common(10),
        "top_destination_ips": dst_counts.most_common(10),
        "top_dns_queries": domain_counts.most_common(10),
        "top_http_hosts": host_counts.most_common(10),
        "findings_count": len(findings),
        "severity_counts": dict(Counter(x["severity"] for x in findings)),
    }
    return summary, findings, sorted(rows[0].keys()) if rows else []

def write_outputs(project_dir, summary, findings, fields):
    report_dir = os.path.join(project_dir, "reports")
    os.makedirs(report_dir, exist_ok=True)
    findings_path = os.path.join(report_dir, "findings.csv")
    with open(findings_path, "w", newline="", encoding="utf-8") as f:
        columns = ["severity", "rule", "src_ip", "dst_ip", "evidence", "recommendation"]
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(findings)

    def bullets(items):
        return "\n".join(f"- `{k}`: {v}" for k, v in items) or "- None observed"

    text = f"""# PCAP CSV Investigation Summary

## Dataset overview
- Input file: `{summary['input_file']}`
- Rows: **{summary['rows_total']}**
- Rows containing an IP endpoint: **{summary['rows_with_ip']}**
- Unique source IPs: **{summary['unique_source_ips']}**
- Unique destination IPs: **{summary['unique_destination_ips']}**
- Unique DNS names: **{summary['unique_dns_names']}**
- Unique HTTP Host values: **{summary['unique_http_hosts']}**
- Total frame bytes (where exported): **{summary['total_frame_bytes']}**

## Protocol values
{bullets(summary['protocol_counts'].items())}

## Top source IPs
{bullets(summary['top_source_ips'])}

## Top destination IPs
{bullets(summary['top_destination_ips'])}

## Top DNS queries
{bullets(summary['top_dns_queries'])}

## Top HTTP Host values
{bullets(summary['top_http_hosts'])}

## Heuristic findings
- Findings generated: **{summary['findings_count']}**
{bullets(summary['severity_counts'].items())}

See [`findings.csv`](findings.csv) for evidence and recommended validation steps.

## Limitations
These are triage heuristics, not definitive incident verdicts. CSV exports may omit TCP flags,
flow state, payloads, or packet details. Validate findings against full PCAPs, endpoint telemetry,
known network baselines, and approved threat-intelligence sources before escalation.
"""
    with open(os.path.join(report_dir, "summary.md"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(report_dir, "analysis.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Path to Wireshark/tshark CSV")
    parser.add_argument("--output", default=".", help="Project directory for reports")
    args = parser.parse_args()
    summary, findings, fields = analyze(args.input)
    write_outputs(args.output, summary, findings, fields)
    print(f"Rows analyzed: {summary['rows_total']}")
    print(f"Rows containing IP endpoints: {summary['rows_with_ip']}")
    print(f"Findings generated: {len(findings)}")
    print(f"Summary: {os.path.abspath(os.path.join(args.output, 'reports', 'summary.md'))}")
    print(f"Findings: {os.path.abspath(os.path.join(args.output, 'reports', 'findings.csv'))}")

if __name__ == "__main__":
    main()
