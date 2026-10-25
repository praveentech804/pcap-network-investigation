# PCAP CSV Investigation Summary

## Dataset overview
- Input file: `traffic.csv`
- Rows: **15512**
- Rows containing an IP endpoint: **14676**
- Unique source IPs: **99**
- Unique destination IPs: **102**
- Unique DNS names: **49**
- Unique HTTP Host values: **8**
- Total frame bytes (where exported): **6333775**

## Protocol values
- `6`: 12544
- `17`: 2113
- `1`: 19

## Top source IPs
- `10.2.28.88`: 7405
- `10.2.28.2`: 2326
- `23.64.147.24`: 823
- `23.218.232.148`: 743
- `45.131.214.85`: 274
- `150.171.28.11`: 256
- `23.192.223.23`: 176
- `23.41.251.53`: 143
- `104.208.203.89`: 140
- `23.192.223.16`: 135

## Top destination IPs
- `10.2.28.88`: 7268
- `10.2.28.2`: 2743
- `10.2.28.255`: 497
- `23.64.147.24`: 445
- `23.218.232.148`: 387
- `45.131.214.85`: 276
- `150.171.28.11`: 219
- `23.192.223.23`: 178
- `104.208.203.89`: 162
- `23.41.251.53`: 124

## Top DNS queries
- `wpad.mshome.net`: 157
- `wpad.easyas123.tech`: 156
- `edge.microsoft.com`: 68
- `login.microsoftonline.com`: 48
- `settings-win.data.microsoft.com`: 38
- `v10.events.data.microsoft.com`: 36
- `www.msn.com`: 25
- `_ldap._tcp.default-first-site-name._sites.dc._msdcs.easyas123.tech`: 20
- `windows.msn.com`: 20
- `www.bing.com`: 20

## Top HTTP Host values
- `45.131.214.85`: 264
- `msedge.b.tlu.dl.delivery.mp.microsoft.com`: 30
- `239.255.255.250:1900`: 27
- `ctldl.windowsupdate.com`: 9
- `ocsp.digicert.com`: 2
- `www.msftconnecttest.com`: 1
- `acroipm2.adobe.com`: 1
- `edge.microsoft.com`: 1

## Heuristic findings
- Findings generated: **14**
- `medium`: 4
- `low`: 4
- `high`: 6

See [`findings.csv`](findings.csv) for evidence and recommended validation steps.

## Limitations
These are triage heuristics, not definitive incident verdicts. CSV exports may omit TCP flags,
flow state, payloads, or packet details. Validate findings against full PCAPs, endpoint telemetry,
known network baselines, and approved threat-intelligence sources before escalation.
