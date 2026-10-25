# PCAP Network Traffic Investigation

A small, explainable SOC triage project for CSV exports produced by Wireshark or tshark.

## Features
- Summarizes IP endpoints, protocols, DNS queries, HTTP hosts, and frame bytes.
- Flags heuristic indicators such as a source contacting many destination ports, high-volume source/destination pairs, unusual WPAD/custom domains, and HTTP Host values that are public IPs.
- Writes `reports/findings.csv`, `reports/summary.md`, and `reports/analysis.json`.
- Includes basic automated tests.

## Run
```bash
python3 src/analyze_pcap.py --input data/raw/traffic.csv --output .
python3 -m unittest discover -s tests -v
```

## Dataset safety
Review the CSV before publishing. Packet exports can contain internal IPs, hostnames, URLs, usernames, or other sensitive information. Keep raw data private unless you have permission to publish it. `.gitignore` excludes the raw CSV by default.

## Important
Detection rules are triage heuristics, not proof of compromise. Confirm with full PCAPs, endpoint telemetry, network baselines, and authorized threat intelligence.
