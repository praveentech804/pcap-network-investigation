# Investigation Methodology

## 1. Scope and preserve evidence

- Record dataset source, capture window and authorization.
- Keep original PCAP/CSV private and preserve an untouched copy.
- Record any conversion or filtering performed before ingest.

## 2. Ingest and validate

- Upload the CSV to Splunk.
- Confirm the intended index and time range.
- Run `spl/00_field_discovery.spl`.
- Verify source/destination IP, protocol, frame length, DNS, HTTP and TLS
  fields. CSV field extraction can differ by sourcetype and Splunk version.

## 3. Establish a baseline

- Run `spl/01_traffic_overview.spl`.
- Run `spl/02_top_talkers.spl`.
- Record event count, unique endpoints, byte totals and dominant sources.
- Treat protocol numbers according to their actual field meaning; do not
  assume a field contains only numeric IP protocol values if it contains
  a decoded protocol stack instead.

## 4. Hunt and validate

- Run DNS, HTTP/TLS, port fan-out and WPAD queries.
- Compare findings with normal host and network behavior.
- Confirm any suspicious lead using packet details and independent evidence.
- Record the exact query, search time range, observed evidence and limitations.

## 5. Report

For each lead, document:
- Observation and timestamp range.
- Relevant IP/domain/host and event count.
- SPL query used.
- Validation performed.
- Benign explanation or unresolved question.
- Confidence and next action.

A query hit is not a confirmed incident.
