# Methodology

1. Read the CSV using its header row and tolerate blank fields.
2. Normalize common Wireshark/tshark field names for source/destination IPs, ports, DNS, HTTP, TLS SNI, protocol, timestamps, and frame length.
3. Produce descriptive counts and rank the most common endpoints and names.
4. Apply conservative triage heuristics:
   - 25 or more distinct destination ports from one source: possible scan.
   - 500 or more rows for a source/destination pair: high-volume pair.
   - `wpad.easyas123.tech` or its subdomains: unusual WPAD/custom-domain review.
   - HTTP Host set to a public IP: review.
5. Export each finding with evidence and a validation recommendation.

Thresholds are configurable in source and are not universal indicators of malicious activity. False positives are expected.
