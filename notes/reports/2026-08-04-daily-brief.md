# Daily Honeynet Intelligence Brief — 2026-08-04

_Window: last 24h. Figures and tables generated deterministically from Elasticsearch; narrative by local LLM._

## Executive Summary
- Increased volume (3.5%) with 7 new IPs (6 high-volume, incl. top attacker `170.101.101.98`).
- Successful Cowrie logins (272), predominantly using "root" (`COUNT: 106`) and "admin".
- Multiple commands executed post-access; notable IOCs observed with medium-to-high confidence.

## What's New
- **Total new IPs:** 11 out of the examined `COUNT: 199` from the baseline (≈5.5%). Key are high-volume newcomers such as:
    - `IP 170.101.101.98` – `SHARE_PCT: 7.9`, targeted Galah (`COUNT: 52267`) and Suricata (`COUNT: 209035`).
    - `IP 73.245.21.31` – `SHARE_PCT: 4.2`, focused on Cowrie/Heralding.
- These sudden, large traffic increases require further analysis to identify possible coordinated attacks or emerging patterns (medium confidence).

11 of 199 examined source IPs (5.5%) were not seen in the prior 30 days (excluding last 24h).

| IP (never seen in 30d) | Events | Share % |
|---|---|---|
| `170.101.101.98` | 380,345 | 7.9 |
| `73.245.21.31` | 204,465 | 4.2 |
| `38.134.40.217` | 51,322 | 1.1 |
| `119.148.8.66` | 7,547 | 0.2 |
| `167.172.240.176` | 5,113 | 0.1 |
| `27.131.66.109` | 4,149 | 0.1 |
| `78.157.212.75` | 3,415 | 0.1 |
| `45.153.34.41` | 3,393 | 0.1 |
| `218.52.254.90` | 2,930 | 0.1 |
| `90.255.227.161` | 2,920 | 0.1 |
| `132.226.13.196` | 2,797 | 0.1 |

## Attacker Behaviour
The following MITRE ATT&CK mappings were derived explicitly from the *observed behaviours* in the evidence, using only techniques listed in `attack_menu`:
1. **T1059 (Command and Scripting Interpreter):** Commands such as "shell", "sh" (`COUNT: 71`, `COUNT: 71` respectively) were executed post-login. *Rationale*: Explicit use of Unix shell commands indicates an interpreter for executing arbitrary code. **Confidence**: High
2. **T1059.004 (Unix Shell):** The execution of specific "sh/bash" and "shell" commands maps to this sub-technique (as per the evidence's `attack_menu`). *Rationale*: Direct invocation of a Unix shell environment observed in Cowrie sessions. **Confidence**: High
3. **T1082 (System Information Discovery):** Commands like "uname -a", "df -h" (`COUNT: 48`, etc.) and probes to "/proc/cpuinfo" indicate attempts at reconnaissance on system details. *Rationale*: Direct queries for OS/kernel version, CPU/memory status, and disk usage are systematic information gathering. **Confidence**: Medium  
*Note:* Other observed command patterns (e.g., "chattr", "Enter new UNIX password", persistence-related commands) did not map cleanly to available techniques in `attack_menu`; thus, these were omitted from the formal list above but warrant logging for potential future enrichment if applicable mappings emerge.

### Cowrie activity
| Metric | Count |
|---|---|
| Sessions | 21,924 |
| Successful logins | 272 |
| Failed logins | 7,806 |
| Commands executed | 1,770 |
| File downloads | 63 |

### Commands executed
| Command | Times |
|---|---|
| `enable` | 71 |
| `sh` | 71 |
| `shell` | 71 |
| `system` | 71 |
| `config terminal` | 66 |
| `linuxshell` | 66 |
| `start` | 66 |
| `su` | 66 |
| `uname -a` | 48 |
| `uname -m` | 48 |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 46 |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` | 45 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` | 45 |
| `cat /proc/cpuinfo | grep name | wc -l` | 45 |
| `crontab -l` | 45 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 45 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 45 |
| `ls -lh $(which ls)` | 45 |
| `lscpu | grep Model` | 45 |
| `top` | 45 |

### Credentials attempted
| Username | Count | Password | Count |
|---|---|---|---|
| `root` | 4,789 | `123456` | 226 |
| `admin` | 487 | `1234` | 138 |
| `ubuntu` | 94 | `123` | 131 |
| `user` | 90 | `password` | 108 |
| `support` | 79 | `12345` | 84 |
| `test` | 56 | `admin` | 80 |
| `guest` | 52 | `12345678` | 77 |
| `deploy` | 46 | `(empty)` | 60 |
| `345gs5662d34` | 42 | `support` | 60 |
| `super` | 36 | `root` | 59 |

## Volume
| Metric | Value |
|---|---|
| Events (last 24h) | 4,842,585 |
| Events (previous 24h) | 4,677,987 |
| Change | +164,598 (+3.5%) |

### By sensor
| Sensor | Events | Share % | Role |
|---|---|---|---|
| P0f | 2,196,778 | 45.4 | MONITORING — passive OS fingerprinting, not a target |
| Suricata | 1,573,964 | 32.5 | MONITORING — NIDS overlay, not a target |
| Heralding | 494,047 | 10.2 | honeypot (credential catcher, many protocols) |
| Beelzebub | 227,578 | 4.7 | honeypot (SSH/HTTP, LLM-backed) |
| Galah | 97,065 | 2.0 | honeypot (HTTP/web, LLM-backed) |
| Fatt | 96,597 | 2.0 | MONITORING — JA3/HASSH pcap metadata, not a target |
| Cowrie | 83,663 | 1.7 | honeypot (SSH/Telnet) |
| H0neytr4p | 59,587 | 1.2 | unknown — verify before describing |
| Tanner | 5,330 | 0.1 | honeypot (web) |
| Mailoney | 3,334 | 0.1 | honeypot (SMTP) |
| ConPot | 2,440 | 0.1 | honeypot (ICS/SCADA) |
| Sentrypeer | 1,769 | 0.0 | honeypot (SIP/VoIP) |
| Dicompot | 24 | 0.0 | unknown — verify before describing |
| Medpot | 2 | 0.0 | unknown — verify before describing |

## Top Attackers by Volume
| IP | Events | Share % | Honeypots hit | Monitoring layers |
|---|---|---|---|---|
| `170.101.101.98` | 380,345 | 7.9 | Galah (52267) | Suricata (209035), P0f (88690), Fatt (30119), invalidJSONResponse (234) |
| `204.76.203.12` | 359,693 | 7.4 | Galah (24572) | Suricata (269150), P0f (45196), Fatt (20775) |
| `73.245.21.31` | 204,465 | 4.2 | Cowrie (37152), Heralding (12438) | Suricata (80112), P0f (74758), Fatt (5) |
| `204.76.203.77` | 174,866 | 3.6 | Galah (10119) | Suricata (134351), P0f (18705), Fatt (11688), invalidJSONResponse (3) |
| `147.182.159.182` | 104,465 | 2.2 | Heralding (24836) | P0f (67218), Suricata (12411) |
| `167.99.186.169` | 104,291 | 2.2 | Heralding (24761) | P0f (67163), Suricata (12367) |
| `134.122.21.135` | 99,584 | 2.1 | Heralding (24467) | P0f (62895), Suricata (12222) |
| `167.99.11.20` | 98,561 | 2.0 | Heralding (22987) | P0f (64090), Suricata (11484) |
| `129.212.181.73` | 90,698 | 1.9 | Heralding (22272) | P0f (57300), Suricata (11126) |
| `137.184.121.249` | 90,506 | 1.9 | Heralding (21650) | P0f (58042), Suricata (10814) |

Combined share of listed attackers: 35.3% of all events.

## Signatures & CVEs
| Suricata signature | Count |
|---|---|
| SURICATA Ethertype unknown | 98,271 |
| SURICATA AF-PACKET truncated packet | 27,192 |
| SURICATA IPv4 truncated packet | 27,192 |
| SURICATA SSH invalid banner | 12,392 |
| SURICATA Applayer Detect protocol only one direction | 8,303 |
| ET INFO SSH session in progress on Expected Port | 4,749 |
| ET INFO SSH Client Banner Detected on Unusual Port | 4,420 |
| SURICATA HTTP Request excessive header repetition | 2,527 |
| SURICATA STREAM spurious retransmission | 2,096 |
| SURICATA STREAM reassembly sequence GAP -- missing packet(s) | 2,081 |

| CVE | Count |
|---|---|
| CVE-2020-11900 | 4 |

## Malware Artifacts
| SHA-256 | Count |
|---|---|
| `28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15` | 48 |
| `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | 46 |
| `c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644` | 46 |
| `cc1eb03e9b5926d8076e25826664a04400de854bf5cc660fa35eb86cbdf7dc0f` | 46 |
| `09a3e612f8cad156005766467cf917c507aa88b3336043a76182a301b404545e` | 45 |
| `28720365c5e7476a011e4f43ac003ee5f16247a263b9d623aa85ed311d73bf39` | 45 |
| `3f1f9a5db692d999bb3d576b5e9956a242136e961ff3f52ba6202b1254ccdb99` | 45 |
| `50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326` | 45 |
| `5c0be87ed7434d69005f8bbd84cad8ae6abfd49121b4aaeeb4c1f4a2e2987711` | 45 |
| `64426356ffcabc3671e5bd0acff75ec85278dc0d4ff5dac8cc07a9dc05a4c420` | 45 |

## Recommended Actions
- **Block candidates** (moderate confidence):  
  Top new attacker IPs: `170.101.101.98`, `73.245.21.31`. These require immediate blocking at the firewall level to minimize exposure.
- **IOC Hunt**: Prioritize hunting for successful logins with "root" and hashes associated with repeated download events:  
  I.e., Hash `HASH 28ba533b0f...` (48 occurrences). Enrichment hits indicate possible malware transfers. 
- **Detection ideas**:
  - Develop a Suricata/YARA rule to alert on persistent commands like "chattr" or frequent modifications to .ssh directories, especially when linked with successful logins from top-source IPs.
  - Create a Sigma detector that flags frequent login attempts after a baseline period exceeds the set threshold (adjust based on prior analysis of `T1110` signatures). 
- **No action needed for commodity noise**: Common scans against monitoring layers (P0f/Suricata) that are well-documented and without notable success indicators should be excluded from focused mitigation efforts.

## Collection Health

- Galah LLM failures: 407 vs 97,065 successful (0.4% failure rate). These are excluded from the sensor table — they are not honeypots.
- Operator-owned infrastructure excluded from rankings: `76.165.200.190` (340,473 events)
- Enrichment: 34 IOCs enriched via IntelOwl (source: 2026-08-03-submissions.json).
- Filtered before enrichment [own]: 1
- Filtered before enrichment [junk_hash]: 1

## Assessment
The 24-hour period reflects moderately intense activity with increased volume driven largely by novel sources appearing in the event stream, most notably high-volume newcomers such as `170.101.101.98` (7.9%). Successful logins and payload downloads (`COUNT:63`) indicate potential risks beyond typical scan noise. The observed command executions suggest targeted reconnaissance efforts, though confidence is moderate due to limited contextual data. Current collection shows adequate coverage across honeypots; however, further enrichment of command execution signatures within `cowrie_behaviour` would improve understanding (medium confidence assessment).
