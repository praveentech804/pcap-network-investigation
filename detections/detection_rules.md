# Detection rules (heuristic)

| Rule | Trigger | Suggested validation |
|---|---|---|
| Possible port scan | One source has 25+ distinct destination ports | Check SYN flags, timing, and host role |
| High-volume source/destination pair | 500+ rows between one source and one destination | Check bytes, duration, and expected services |
| Unusual WPAD/custom domain | `wpad.easyas123.tech` or `.easyas123.tech` DNS query | Verify domain ownership and endpoint context |
| HTTP Host is a public IP address | HTTP Host parses as a public IP | Review URI, response, and approved reputation sources |

These rules generate leads for an analyst, not confirmed incident labels.
