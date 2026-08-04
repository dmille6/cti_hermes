# The existing tsec pipeline — what NOT to rebuild (2026-08-04)

The operator already runs a mature collection + enrichment platform in the
T-Pot Elasticsearch cluster (`tsec-*`, `threat-intel-*`, `malware-*`,
`security-honeypot-*` indices) feeding OpenCTI. **cti_hermes must consume
this, not duplicate it.** This note records what is already covered, so no
future session rebuilds it a third time.

## Scale

Multi-site hive — sensors include `db1lapetro`, `db4lamedtech`, `hivev2`,
`rmm-prod-01`, `pbx-prod-01`. Roughly 1M sessions and 1.5M Suricata alerts
per 24h; 123,795 unique IPv4 tracked in total.

## ALREADY RUNNING — do not rebuild

| Capability | Where | Status |
|---|---|---|
| Novelty tracking | `tsec-observatory-*` → `unique_ipv4_new_24h` / `_7d` | live; 15,062 new IPs/24h across the **full** population |
| IP reputation on every event | `logstash-*` → `ip_rep` field | live; "known attacker" 1.26M, "mass scanner" 56.6k, tor exit, anonymizer, crawler |
| GTI enrichment | tsec connectors | **100% coverage** |
| AbuseIPDB / MaxMind / FireHOL | tsec connectors | **82.3% coverage** |
| LLM enrichment | tsec connectors | **95.9% coverage** |
| Malware sample handling | `tsec-malware-vault-*`, `malware-sightings`, `threat-intel-malware-samples` | live; family, VT verdict, is_new_sample, sector |
| Sandboxing | `tsec-gti-sandbox-*`, `tsec-cs-sandbox-*`, `tsec-triage-sandbox-*` | live |
| Feed submission | `tsec-{gti,otx,abuseipdb,abusech}-export-submissions-*` | live |
| Pipeline health digest | `tsec-daily-digest-*` | live; narrative + action_items + anomalies, **ops-focused** |
| Connector telemetry | `tsec-connector-{heartbeat,metrics,errors}-*` | live |

### Implication for cti_hermes

`src/enrich_iocs.py` re-enriches a handful of IOCs per day through IntelOwl.
That is **redundant and far smaller** than the existing 82–100% coverage.
Its remaining value is ad-hoc analyst lookups, not routine coverage.
The daily brief should read `ip_rep` and the tsec enrichment fields instead
of submitting fresh IOCs.

## DORMANT — the actual opportunity

These indices contain exactly the adversary-behaviour analysis cti_hermes was
reaching for, but they stopped updating:

| Index | Contents | Last updated |
|---|---|---|
| `threat-intel-export-staging` | `commands`, `mitre_techniques`, `campaigns`, `credentials`, `ssh_keys`, `malware_families` | **2026-02-12** (~6 months stale) |
| `security-honeypot-patterns` | behavioural `fingerprint`, LLM `analysis` (attack type, objective, techniques), `times_seen`, `sample_iocs` | **2025-12-16** (~8 months stale) |

A sample from the dormant staging index shows it was producing real work:
15 MITRE techniques (T1105, T1098.004, T1489, T1497.001 …), command clusters
grouped by hash with source-IP lists, and SSH key tracking.

`security-honeypot-patterns` shows LLM-written behavioural analysis
("Backdoor installation and system reconnaissance… SSH key injection…") — the
same job cti_hermes now does, built earlier and then abandoned.

## What is genuinely missing today

The live `tsec-daily-digest` narrative is about **pipeline health** (connector
errors, throughput, HTTP 503s), not about adversaries. Its `honeypot_summary`
is five numbers. So the gap is:

1. **Adversary-behaviour reporting** — Cowrie commands, successful logins,
   session reconstruction, ATT&CK mapping. Live data exists (1,770
   command.input events/day) but nothing currently analyses it.
2. **Campaign clustering over time** — `campaigns` was always `[]` even when
   staging ran.
3. **Analyst-facing narrative** distinct from ops health.

## Recommended posture

- **Do not** run routine IntelOwl enrichment; the tsec pipeline already covers
  it. Keep IntelOwl for ad-hoc analyst pivots.
- **Do** read `ip_rep`, `tsec-observatory-*`, `malware-sightings`, and the
  tsec enrichment fields as inputs to the brief.
- **Decide with the operator**: revive `threat-intel-export-staging` /
  `security-honeypot-patterns`, or let cti_hermes own that layer. Doing both
  is how this got duplicated in the first place.
