# Unholy Land Writeup

## Files and setup

- Created a working folder at `/home/andrei2308/unbreakable/unholy_land`.
- The signed URL provided later had expired, so the small XML error file was replaced with the previously downloaded full dataset.
- Final evidence file used for analysis: `eve.json`.
- Total lines in `eve.json`: `15551`.

## Challenge questions

### 1. TCP, UDP, and ICMPv6 counts

This question was initially ambiguous because the EVE file contains multiple ways to count traffic:

- Suricata cumulative decoder counters from `event_type == "stats"`
- all records containing a `proto` field
- only `flow` records

The accepted interpretation was counting only `flow` records by `proto`.

Python logic used:

```python
import json
from collections import Counter

c = Counter()
for line in open("eve.json", encoding="utf-8"):
    obj = json.loads(line)
    if obj.get("event_type") == "flow":
        c[obj.get("proto")] += 1

print(c)
```

Result:

- `TCP`: `3391`
- `UDP`: `2452`
- `IPv6-ICMP`: `15`

Accepted answer:

- `UNR{3391, 2452, 15}`

### 2. Number of events in the file

The file is newline-delimited JSON, so the total number of events is the number of lines.

Command used:

```bash
wc -l eve.json
```

Result:

- `15551`

Answer:

- `UNR{15551}`

### 3. Top 3 DNS requests

For this question, only DNS request events were counted, using `dns.type == "request"` and `dns.queries[].rrname`.

Python logic used:

```python
import json
from collections import Counter

c = Counter()
for line in open("eve.json", encoding="utf-8"):
    obj = json.loads(line)
    if obj.get("event_type") != "dns":
        continue
    dns = obj.get("dns", {})
    if dns.get("type") != "request":
        continue
    for q in dns.get("queries", []) or []:
        rr = q.get("rrname")
        if rr:
            c[rr] += 1

print(c.most_common(10))
```

Top three:

1. `ncs.roblox.com` - `172`
2. `users.roblox.com` - `141`
3. `edge.microsoft.com` - `136`

Answer:

- `UNR{ncs.roblox.com, users.roblox.com, edge.microsoft.com}`

## Malware identification

### Evidence from the EVE file

The local dataset contains explicit references to `BlackSun`:

- `http_user_agent: "BlackSun"`
- Suricata alert signature: `ET USER_AGENTS Suspicious User Agent (BlackSun)`

Observed suspicious HTTP flow:

- host: `testmyids.com`
- user-agent: `BlackSun`

### OSINT pivots

The hash associated with the BlackSun sample was pivoted externally:

- SHA256: `e5429f2e44990b3d4e249c566fbf19741e671c0e40b809f87248d9ec9114bef9`

References found:

- VMware: `BlackSun Ransomware – The Dark Side of PowerShell`
- Malpedia family: `ps1.blacksun`
- Microsoft detection: `Trojan:Win32/BlackSun!mclg`
- VirusTotal labels centered on `blacksun`
- Triage and cached ANY.RUN results associate this exact SHA256 with the filename `BlackSun.ps1`

## Final state so far

Confirmed / accepted:

- Q1: `UNR{3391, 2452, 15}`

Derived and ready:

- Q2: `UNR{15551}`
- Q3: `UNR{ncs.roblox.com, users.roblox.com, edge.microsoft.com}`