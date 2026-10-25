# PCAP Network Traffic Investigation with Splunk

A hands-on SOC Analyst portfolio project using Splunk Enterprise and SPL
(Search Processing Language) to investigate network traffic exported from
Wireshark/tshark as CSV.

## Objectives

- Ingest packet metadata into Splunk.
- Establish a traffic baseline.
- Identify top source and destination IPs.
- Investigate DNS queries, HTTP hosts and TLS server names.
- Hunt for unusual destination-port fan-out and suspicious-looking indicators.
- Document evidence, limitations, and follow-up investigation steps.

## Technology

- Splunk Enterprise
- SPL
- Wireshark / tshark CSV export
- Kali Linux

This repository is a Splunk investigation project. It does not require a
Python analyzer or Python-based detection pipeline.

## Dataset and privacy

The original dataset is expected at `data/raw/traffic.csv` on the analyst's
machine. Raw CSV, PCAP and PCAPNG files are excluded from Git by default.
Only publish data that you own or have permission to share. Review any
derived output for internal IP addresses, hostnames and sensitive metadata.

## Setup

1. Start Splunk Enterprise and open Splunk Search & Reporting.
2. Select **Settings → Add Data → Upload**.
3. Upload `data/raw/traffic.csv` (or choose the CSV at its original location).
4. Select the `main` index, or replace `index=main` in the queries with
   the index you actually use.
5. Review the field preview before submitting.
6. Set the search time picker to **All time** for this offline dataset.
7. Open `spl/00_field_discovery.spl` and run the query in Search & Reporting.
8. Confirm the CSV headers are extracted as fields before running the remaining
   SPL files. If a field is absent, review the CSV sourcetype and field names.

## Investigation workflow

Run the SPL files in order:

| File | Purpose |
|---|---|
| `spl/00_field_discovery.spl` | Verify indexed events and field extraction |
| `spl/01_traffic_overview.spl` | Dataset and protocol baseline |
| `spl/02_top_talkers.spl` | Source and destination activity |
| `spl/03_dns_hunting.spl` | DNS query review |
| `spl/04_http_tls_hunting.spl` | HTTP host and TLS SNI review |
| `spl/05_port_fanout.spl` | Sources contacting many destination ports |
| `spl/06_wpad_hunting.spl` | WPAD-related DNS review |
| `spl/07_timeline.spl` | Event activity over time |
| `spl/08_public_ip_http_hosts.spl` | HTTP Host values that look like IPv4 addresses |

These queries assume the standard tshark CSV headers shown in the source
dataset. The field-discovery step is mandatory; adjust quoted field references
if your actual CSV headers differ.

## Evidence and reporting

Record actual Splunk results in `reports/investigation_findings.md`.
Do not claim an alert is malicious solely because it matches a heuristic.
Validate with packet-level evidence, asset ownership, baseline traffic and
authorized threat-intelligence sources.

## Limitations

A CSV packet-metadata export is not equivalent to full packet payloads,
endpoint logs or a complete network-flow record. Missing fields, timestamp
parsing and incomplete capture can affect findings. A high-volume host,
unusual domain or broad port fan-out is an investigation lead, not proof
of compromise.

## References

- Splunk Search Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/
- Splunk `stats`: https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/stats
- Splunk `eval`: https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/eval
- Splunk `rex`: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rex
