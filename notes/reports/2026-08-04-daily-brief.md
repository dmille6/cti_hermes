# Daily Honeynet Intelligence Brief — 2026-08-04

_Window: last 24h. Figures and tables generated deterministically from Elasticsearch; narrative by local LLM._

## Executive Summary
- A new high-volume source, `170.101.101.98`, was observed with over 380,000 events.
- Successful logins increased to 271 from various sources, including a notable login from `118.38.44.223` with 10 successful attempts.
- Notable commands such as `uname -a`, `sh`, and `whoami` were executed frequently, indicating reconnaissance activities.

## What's New
The novelty block indicates that out of the top IPs examined, 17 (or 8.5%) are new sources against a 30-day baseline. The most significant new source is `170.101.101.98`, which generated over 380,000 events and targeted Galah honeypots. This source's high volume and novelty make it the most report-worthy item.

17 of 199 examined source IPs (8.5%) were not seen in the prior 30 days (excluding last 24h).

| IP (never seen in 30d) | Events | Share % |
|---|---|---|
| `170.101.101.98` | 380,345 | 7.6 |
| `38.134.40.217` | 51,322 | 1.0 |
| `152.179.140.153` | 24,630 | 0.5 |
| `38.76.219.69` | 22,709 | 0.5 |
| `8.211.130.186` | 15,863 | 0.3 |
| `91.233.10.193` | 13,861 | 0.3 |
| `186.241.104.72` | 11,557 | 0.2 |
| `119.148.8.66` | 7,547 | 0.1 |
| `167.172.240.176` | 5,113 | 0.1 |
| `103.231.56.55` | 4,692 | 0.1 |
| `78.157.212.75` | 4,115 | 0.1 |
| `45.153.34.41` | 3,393 | 0.1 |
| `90.255.227.161` | 2,920 | 0.1 |
| `132.226.13.196` | 2,797 | 0.1 |
| `137.220.155.194` | 2,748 | 0.1 |

## Attacker Behaviour
- **T1110 (Brute Force)**: Observed with repeated login attempts.
- **T1110.001 (Password Guessing)**: Indicated by many password attempts against a few accounts, such as `root` and `admin`.
- **T1078 (System Information Discovery)**: Commands like `uname -a`, `df -h | head -n 2`, and `cat /proc/cpuinfo` were used to gather system information.
- **T1059.004 (Unix Shell)**: Common Unix shell commands such as `sh` and `bash` were executed, indicating an attempt to gain a command-line interface.

### Cowrie activity
| Metric | Count |
|---|---|
| Sessions | 7,503 |
| Successful logins | 271 |
| Failed logins | 5,520 |
| Commands executed | 1,522 |
| File downloads | 56 |

### Commands executed
| Command | Times |
|---|---|
| `uname -a` | 77 |
| `enable` | 58 |
| `sh` | 58 |
| `shell` | 58 |
| `system` | 58 |
| `config terminal` | 54 |
| `linuxshell` | 53 |
| `start` | 53 |
| `su` | 53 |
| `uname -m` | 43 |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` | 37 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` | 37 |
| `cat /proc/cpuinfo | grep name | wc -l` | 37 |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 37 |
| `crontab -l` | 37 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 37 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 37 |
| `ls -lh $(which ls)` | 37 |
| `lscpu | grep Model` | 37 |
| `top` | 37 |

### Credentials attempted
| Username | Count | Password | Count |
|---|---|---|---|
| `root` | 2,733 | `123456` | 214 |
| `admin` | 415 | `1234` | 123 |
| `user` | 108 | `123` | 109 |
| `ubuntu` | 103 | `password` | 103 |
| `support` | 74 | `12345` | 82 |
| `guest` | 52 | `admin` | 73 |
| `test` | 48 | `root` | 70 |
| `deploy` | 44 | `12345678` | 65 |
| `345gs5662d34` | 33 | `support` | 55 |
| `debian` | 29 | `(empty)` | 54 |

## Volume
| Metric | Value |
|---|---|
| Events (last 24h) | 5,035,530 |
| Events (previous 24h) | 4,932,914 |
| Change | +102,616 (+2.1%) |

### By sensor
| Sensor | Events | Share % | Role |
|---|---|---|---|
| P0f | 2,138,727 | 42.5 | MONITORING — passive OS fingerprinting, not a target |
| Suricata | 1,867,249 | 37.1 | MONITORING — NIDS overlay, not a target |
| Heralding | 474,759 | 9.4 | honeypot (credential catcher, many protocols) |
| Beelzebub | 203,412 | 4.0 | honeypot (SSH/HTTP, LLM-backed) |
| Galah | 126,238 | 2.5 | honeypot (HTTP/web, LLM-backed) |
| Fatt | 114,299 | 2.3 | MONITORING — JA3/HASSH pcap metadata, not a target |
| H0neytr4p | 59,433 | 1.2 | unknown — verify before describing |
| Cowrie | 35,323 | 0.7 | honeypot (SSH/Telnet) |
| Tanner | 5,231 | 0.1 | honeypot (web) |
| ConPot | 4,998 | 0.1 | honeypot (ICS/SCADA) |
| Mailoney | 3,389 | 0.1 | honeypot (SMTP) |
| Sentrypeer | 2,013 | 0.0 | honeypot (SIP/VoIP) |
| Dicompot | 24 | 0.0 | unknown — verify before describing |
| Medpot | 2 | 0.0 | unknown — verify before describing |
| Honeytrap | 1 | 0.0 | honeypot (generic TCP/UDP) |

## Top Attackers by Volume
| IP | Events | Share % | Honeypots hit | Monitoring layers |
|---|---|---|---|---|
| `170.101.101.98` | 380,345 | 7.6 | Galah (52267) | Suricata (209035), P0f (88690), Fatt (30119), invalidJSONResponse (234) |
| `204.76.203.12` | 359,693 | 7.1 | Galah (24572) | Suricata (269150), P0f (45196), Fatt (20775) |
| `204.76.203.91` | 303,666 | 6.0 | Galah (32450) | Suricata (179227), P0f (70659), Fatt (21325), invalidJSONResponse (5) |
| `204.76.203.77` | 174,866 | 3.5 | Galah (10119) | Suricata (134351), P0f (18705), Fatt (11688), invalidJSONResponse (3) |
| `147.182.159.182` | 103,371 | 2.1 | Heralding (24599) | P0f (66471), Suricata (12301) |
| `167.99.186.169` | 103,138 | 2.0 | Heralding (24519) | P0f (66357), Suricata (12262) |
| `134.122.21.135` | 98,567 | 2.0 | Heralding (24232) | P0f (62214), Suricata (12121) |
| `167.99.11.20` | 98,130 | 1.9 | Heralding (22907) | P0f (63763), Suricata (11460) |
| `129.212.181.73` | 90,131 | 1.8 | Heralding (22155) | P0f (56893), Suricata (11083) |
| `137.184.121.249` | 90,042 | 1.8 | Heralding (21537) | P0f (57729), Suricata (10776) |

Combined share of listed attackers: 35.8% of all events.

## Signatures & CVEs
| Suricata signature | Count |
|---|---|
| SURICATA Ethertype unknown | 98,237 |
| SURICATA AF-PACKET truncated packet | 36,236 |
| SURICATA IPv4 truncated packet | 36,236 |
| ET INFO SSH session in progress on Expected Port | 4,424 |
| SURICATA HTTP Request excessive header repetition | 3,676 |
| SURICATA STREAM spurious retransmission | 2,589 |
| SURICATA STREAM reassembly sequence GAP -- missing packet(s) | 2,156 |
| SURICATA HTTP request missing protocol | 2,103 |
| SURICATA STREAM Packet with broken ack | 1,607 |
| SURICATA HTTP Host header ambiguous | 1,286 |

| CVE | Count |
|---|---|
| CVE-2020-11900 | 6 |

## Malware Artifacts
| SHA-256 | Count |
|---|---|
| `28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15` | 77 |
| `09a3e612f8cad156005766467cf917c507aa88b3336043a76182a301b404545e` | 37 |
| `28720365c5e7476a011e4f43ac003ee5f16247a263b9d623aa85ed311d73bf39` | 37 |
| `3f1f9a5db692d999bb3d576b5e9956a242136e961ff3f52ba6202b1254ccdb99` | 37 |
| `50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326` | 37 |
| `5c0be87ed7434d69005f8bbd84cad8ae6abfd49121b4aaeeb4c1f4a2e2987711` | 37 |
| `64426356ffcabc3671e5bd0acff75ec85278dc0d4ff5dac8cc07a9dc05a4c420` | 37 |
| `95df9ab820c0b94e87412330a566c7e47ceef0cfc297bbe2c51a198d1b017abe` | 37 |
| `a28dd0be4d71a20d853d1770a896f623b4558fd8f00a6e06cc489263029b66f0` | 37 |
| `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | 37 |

## Recommended Actions
Block candidates:
- IP: 170.101.101.98

IOCs worth hunting:
- File hashes with high OTX pulse counts (e.g., `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`)

Detection ideas:
- Suricata signature for SSH session in progress on expected port
- YARA rule for common Unix shell commands

No action needed:
- Commodity noise from IPs with low OTX pulse counts and no significant malicious activity.

## Collection Health

- Galah LLM failures: 432 vs 126,238 successful (0.3% failure rate). These are excluded from the sensor table — they are not honeypots.
- Operator-owned infrastructure excluded from rankings: `76.165.200.190` (342,657 events)
- Enrichment: 34 IOCs enriched via IntelOwl (source: 2026-08-03-submissions.json).
- Filtered before enrichment [own]: 1
- Filtered before enrichment [junk_hash]: 1

## Assessment
The collection shows a mix of commodity noise and notable activity, with high confidence due to the presence of new sources and successful logins. The increase in reconnaissance activities via system information discovery commands suggests an elevated risk level. However, there is insufficient evidence for targeted attacks beyond typical scanning and brute force attempts.
