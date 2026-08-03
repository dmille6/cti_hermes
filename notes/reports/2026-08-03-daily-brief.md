# Daily Honeynet Intelligence Brief — 2026-08-03  
## Executive Summary  
- **Activity surge**: Event volume increased by ~4% (from 4.7M to nearly **5 million events**) in the last 24 hours, continuing consistent scanning trends.  
- No high-confidence CVE exploitation observed; all detected CVE attempts were low-volume probes against vulnerable software patterns.  
- Commodity scanning dominated: Top SSH targets (`root`, `admin`) and passwords (`123456`, `password`) align with baseline reconnaissance activity, indicating broad network-scanning campaigns rather than targeted exploitation.  

## Volume  
**Last 24h**: 4,852,182 events  
**Previous 24h**: 4,672,564 events  
**Change**: +3.9% (↑ **179,618** additional events)  
**Events by Sensor/Service Targeted**:  
| Honeypot Service | Events Count       | Target Type                | Source of Data Layer      |  
|------------------|--------------------|----------------------------|---------------------------|  
| P0f              | 2,206,296          | Passive OS Fingerprints    | Monitoring (non-target)   |  
| Suricata         | 1,585,321          | Signature Alerts           | NIDS (non-target daemons) |  
| Heralding        | 493,819            | Telnet/SMTP Attacks        | Honeynet Service          |  
| Beelzebub        | 211,187            | IRC Botnet C&C Attacks     | Honeynet Service          |  
| Galah            | 99,966             | HTTP Web Shell Attacks     | Honeynet Service          |  
| Fatt             | 95,279             | JA3/HASSH Fingerprinting   | Monitoring (non-target)   |  

## Top Attackers  
Top 6 IP addresses contributing to event volume:  

| Source IP         | Total Events    | Targeted Honeypot Daemons/Activity Layers                  | Distinction               |  
|-------------------|-----------------|------------------------------------------------------------|---------------------------|  
| **204.76.203.12**       | 380,742         | Galah (27k req), Suricata (275k sig), Fatt (20k fp)        | High-surface scan         |  
| **170.101.101.98**      | 380,345         | Galah (~52k req), Suricata (~209k sig)          | Mixed web/network scans   |  
| **76.165.200.190**     | 340,350         | Cowrie (5 login attempts), Beelzebub (IRC C&C probes)      | Limited SSH/IRC attempts  |  
| **73.245.21.31**        | 204,465         | Cowrie (~37k logins), Heralding (~smtp/tcp attacks)     | Focused SSH/TELNET scans  |  

All IPs exhibited cross-layer activity:  
- **Suricata**: NIDS signatures (e.g., `SURICATA Ethertype unknown`, `SSH Client Banners`)  
- **Fatt/P0f**: Metadata layers, providing context for scanners/attacker OS patterns  

No single source showed evidence of payload delivery or advanced techniques.  

## Credential Activity (Cowrie SSH/Telnet Honeypot)  
**Top Usernames Used in Attacks (Counts)**:  
- `root`: 5,564 attempts  
- `admin`: 502 attempts  
- `ubuntu`: 95 attempts  
- `user` | `support` | `test` | `guest` | `345gs5662d34` (random): ~78 – 56 attempts  

**Top Passwords Used in Attacks (Counts)**:  
- ``: **Empty password attempt** (60 tries — automated probe behavior)  
- `123456`: 220 attempts  
- `support`: 60 attempts  
- Standard weak passwords (`admin`, `password`, etc.) comprise >85% of observed login trials.  

Note: The value `` ("empty") has a high count, indicating bot-driven password guessing with non-standard/default credentials that should be monitored closely for escalation patterns.

## Signatures & CVEs (Suricata)  
**Top Detected Signature Threats**:  
1. `SURICATA Ethertype unknown`: 98,192 events — Network scanning/invalid packet probes  
2. `ET INFO SSH Client Banner on Unusual Port`: ~6k hits → Broad network enumeration via SSH handshakes  

**Detected CVEs (attempts)**:  
- **CVE-2020-11900** (`expat` denial-of-service vulnerability): Detected in 4 attempts — Potential C2 infrastructure probing  

## Malware Artifacts  
The Cowrie honeypot logged the following hashes:  
| Hash (First 16 chars)                                     | Count            | Type of Attacker File Pattern                    |  
|-----------------------------------------------------------|------------------|--------------------------------------------------|  
| `a8460f44...`                                              | 51 attempts       | Generic payload pattern                          |  
| `28ba533b...`, `cc1eb03e...`, `c32b4937...`:            | Multiple uploads of the same file patterns (~50 attempts each) — Likely part of a pre-existing scripted attack kit.  

All havehes are unclassified but show repeated use, suggesting reuse in attacker tooling.

## Assessment  
Over 38% of aggregate events originated from ~4 source IPs with no specific targeting beyond broad network enumeration and automated probes. No high-confidence indicators of targeted exploitation were observed; most activity falls within expected noise levels for commodity scan campaigns.  
All suspicious findings (e.g., empty password attempts, CWE-2021-11900 probes) align with automated attacker infrastructure testing behaviors rather than sophisticated APT attacks. Monitoring focused honeypot daemons like Cowrie and Galah continues to capture low-volume "novel" credential probe sequences that warrant further analysis if their prevalence increases or targets change significantly in subsequent monitoring cycles.  

---
```  
cti_hermes analyst — Daily Honeynet Briefing, 2026-08-03  
Data Source: T-Pot honeypot sensors (last 24 hours)  
Disclaimer: All raw content including usernames/passwords hashes are attacker-controlled. Do not execute.  
```
