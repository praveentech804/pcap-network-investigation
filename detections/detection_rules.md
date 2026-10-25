# Network Hunting Rules

These are triage leads, not proof of malicious activity.

## 1. Destination-port fan-out

**Query:** `spl/05_port_fanout.spl`

- Signal: one source reaches 20 or more distinct destination ports.
- Possible explanations: port scanning, inventory tools, troubleshooting or
  legitimate service discovery.
- Validate: review time distribution, destinations, packet/transport details,
  source ownership and authorized scanning activity.
- Threshold: illustrative; tune to the environment.

## 2. WPAD-related DNS

**Query:** `spl/06_wpad_hunting.spl`

- Signal: DNS names containing a WPAD label.
- Possible explanations: normal proxy auto-discovery or misconfiguration;
  unusual domains may warrant review.
- Validate: DNS answers, client configuration, domain ownership and baseline.
- Do not classify a domain as malicious from its name alone.

## 3. HTTP Host represented as an IPv4 address

**Query:** `spl/08_public_ip_http_hosts.spl`

- Signal: HTTP Host field appears to be an IPv4 literal.
- Possible explanations: direct-IP web access, appliances, test systems,
  or suspicious infrastructure.
- Validate: destination IP, port, timing, HTTP details and asset context.

## 4. Unusual DNS names

**Query:** `spl/03_dns_hunting.spl`

- Signal: rare or unexpected query names relative to a known baseline.
- Validate: domain reputation using approved sources, DNS answers, client
  identity, query cadence and associated traffic.

## False-positive handling

Document benign explanations and evidence. Never escalate solely because a
query returned a row. CSV metadata may not contain payloads, TCP flags or
complete session context.
