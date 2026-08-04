# CTI Hermes Sanity Check And Gap Analysis — 2026-08-03

## 1. Sanity Check

The current state is coherent for a defensive CTI lab pipeline: deterministic Python collects and calculates, IntelOwl enriches, MISP warninglists protect quota, OpenCTI is read-only, Hermes writes prose under a locked-down `rawingest` profile, and reports stay local. That is the right direction.

The biggest mismatch is documentation drift. [notes/architecture.md](/Users/darrellmiller/Documents/cti_hermes/notes/architecture.md:70) and [notes/intelowl.md](/Users/darrellmiller/Documents/cti_hermes/notes/intelowl.md:144) still point toward IntelOwl connectors writing into MISP/OpenCTI, but the actual current operating model is pull-only with connectors disabled. Treat the pull-only rule as authoritative and update the docs so the next assistant does not “complete” a now-forbidden write path.

Things that look right but are not quite right:

- The OpenCTI read-only account is good, and verified write denial is important. Keep it that way until STIX objects are deterministic, validated, reviewed, and written by a separate service account.
- T-Pot ES without auth is acceptable only for this internal PoC. It is still the largest blast radius because the agent host can query broad raw attacker-controlled data.
- IntelOwl pull-only is coherent, but the report only joins the latest submissions file, not necessarily the correct enrichment set for the report window. [src/daily_brief.py](/Users/darrellmiller/Documents/cti_hermes/src/daily_brief.py:142)
- The enrichment ledger prevents quota burn, but because it records an IOC once forever, reputation, ASN ownership, pulse membership, VT detections, and MISP context all go stale. [src/enrich_iocs.py](/Users/darrellmiller/Documents/cti_hermes/src/enrich_iocs.py:152)
- The top-IP enrichment selector is volume-biased. It does not prioritize new IPs, new ASNs, new hashes, new credential strings, or behavior changes. [src/enrich_iocs.py](/Users/darrellmiller/Documents/cti_hermes/src/enrich_iocs.py:89)
- `invalidJSONResponse` and `contentGenerationError` are still treated as sensor values in aggregation output unless filtered or remapped. The report warns “unknown,” but the pipeline should classify them as Galah failure artifacts, not sensors.
- The latest report still shows `76.165.200.190` as a top attacker while later enrichment says it was excluded as own infrastructure. That is confusing and materially misleading. [notes/reports/2026-08-03-daily-brief.md](/Users/darrellmiller/Documents/cti_hermes/notes/reports/2026-08-03-daily-brief.md:41)

## 2. Report Quality

As a CTI consumer, I would not yet use the daily brief for decisions. It is a telemetry summary with enrichment snippets, not an intelligence product.

Major weaknesses:

- It leads with volume, not change. Your own finding that only 11 of the top 200 IPs are new, and that `170.101.101.98` is both #1 and new, is more important than a 3.6% event increase.
- It ignores high-value Cowrie behavior: 1760 `command.input` events and 272 successful logins/day. That is closer to adversary tradecraft than P0f/Suricata volume.
- It treats top attackers as top event generators. That overweights monitoring noise and underweights hands-on-keyboard-ish behavior, successful auth, payload retrieval, commands, malware staging, and new infrastructure.
- It includes polluted sensor types in the main volume and top attacker tables. [notes/reports/2026-08-03-daily-brief.md](/Users/darrellmiller/Documents/cti_hermes/notes/reports/2026-08-03-daily-brief.md:29)
- The Markdown table is malformed, which is small mechanically but costly for trust. [notes/reports/2026-08-03-daily-brief.md](/Users/darrellmiller/Documents/cti_hermes/notes/reports/2026-08-03-daily-brief.md:15)
- Enrichment is over-interpreted. AbuseIPDB/VT/OTX hits say “known bad on the internet,” not “important in this collection.” The interesting question is what changed locally.
- The malware section is vague and partially incoherent. It lists hashes and reputation but does not say source sensor, delivery path, filename, URL, session linkage, architecture, family guess, or whether the hash is new locally.
- The CVE section is too thin. A Suricata CVE hit four times is a lead, not a finding. It needs signature, source/destination, request evidence, affected honeypot, and confidence.
- There are no recommended actions: no block candidates, hunt queries, Sigma/YARA ideas, OpenCTI objects to review, or “do not action” notes.
- There is no collection health section: which sensors produced useful activity, which produced only monitoring noise, which fields are unreliable, and what data was excluded.

## 3. Analytic Tradecraft Gaps

The core tradecraft gap is absence of “so what changed?” logic.

Needed analytic layers:

- Baselines: compare current 24h against prior 7/30/35 days for IPs, ASNs, countries, ports, sensors, usernames, passwords, commands, URLs, hashes, Suricata signatures, and CVEs.
- Novelty scoring: new source IP, new ASN, new CIDR, first-seen credential, first-seen command, first-seen hash, rare sensor combination, and sudden reappearance after dormancy.
- Behavior-first clustering: group by session behavior, not IOC reputation. Example clusters: SSH brute force with successful login, post-login command execution, web exploit probing, malware download, scanner-only noise.
- Cowrie session reconstruction: successful login -> commands -> downloaded URLs -> hashes -> outbound callbacks. This should be a top report section.
- ATT&CK mapping from behavior only. Credential attempts, successful auth, shell commands, wget/curl downloaders, persistence attempts, and discovery commands can map with rationale; IP reputation cannot.
- Infrastructure analysis: ASN/provider, rDNS, Shodan open services, datacenter/VPN annotation, co-occurrence across sensors, and repeat infrastructure over 35 days.
- Confidence discipline: every finding should have evidence, confidence, and an explicit “why this matters.”
- Source reliability: distinguish local honeypot observation, MISP warninglist context, OTX pulse membership, VT detections, AbuseIPDB reports, Shodan observations, and operator-owned exclusions.
- Decay and re-enrichment: reputation and context need TTLs by observable class, not a permanent seen ledger.
- Negative findings: explicitly say when activity is commodity scan noise, when not to block, when enrichment is stale, and when evidence is insufficient.

## 4. Opportunities Ranked By Value/Effort

| Rank | Opportunity | Value | Effort | Notes |
|---:|---|---|---|---|
| 1 | Add novelty/trend features to `daily_brief.py` using 35-day ES retention | Very high | Low-medium | This immediately fixes the volume bias. |
| 2 | Add Cowrie session analytics: successful logins, commands, URLs, hashes | Very high | Medium | Most useful tradecraft currently ignored. |
| 3 | Filter/remap Galah LLM failure values out of `type.keyword` sensor summaries | High | Low | Prevents fake sensors from polluting reports. |
| 4 | Split top activity into `top_volume`, `top_new`, `top_successful_auth`, `top_payload`, `top_enriched_bad` | High | Low-medium | Makes the report decision-friendly. |
| 5 | Add enrichment TTLs and re-enrichment policy | High | Low-medium | IPs perhaps 7 days, hashes 30 days, high-interest IOCs shorter. |
| 6 | Generate deterministic report tables and let Hermes write only summaries | High | Medium | Avoids malformed Markdown and invented claims. |
| 7 | Use RTX 5080 for structured extraction/classification of Cowrie commands and Galah web paths | Medium-high | Medium | Keep output schema-validated; no tools. |
| 8 | Use A6000 pending host for local embedding and clustering over 35-day sessions | Medium-high | Medium | Cluster commands, URLs, payloads, and signatures. |
| 9 | Add weekly analytic product with ATT&CK heatmap and infrastructure clusters | Medium-high | Medium | Better home for trend/campaign analysis. |
| 10 | Use OpenCTI as curated read model only until review queue exists | Medium | Medium | Keep pull-only now; later write only reviewed STIX. |
| 11 | Mine existing `tsec-*` indices before duplicating feed work | Medium | Low-medium | Existing GTI/OTX/AbuseIPDB/sandbox/llm-calls pipeline is an asset. |
| 12 | Add CrowdStrike/GTI/OTX context as enrichment fields, not prose-only claims | Medium | Medium | Make provider evidence auditable. |

## 5. Ordered Next Steps

1. Update architecture and IntelOwl notes to state the current rule: IntelOwl connectors disabled, pull-only, no writes to MISP/OpenCTI.
2. Fix the report’s own-infra handling so operator-owned IPs are excluded or clearly separated from attacker rankings.
3. Filter or remap `invalidJSONResponse` and `contentGenerationError` before sensor aggregation.
4. Add 35-day first-seen/last-seen counts for top IPs, hashes, usernames, passwords, commands, CVEs, and signatures.
5. Replace the single “Top Attackers” section with ranked sections for volume, novelty, successful login activity, command activity, payload/hash activity, and enriched high-confidence IOCs.
6. Add Cowrie analytics: successful logins, `command.input`, command sequences, URLs, downloaded hashes, and per-session summaries.
7. Add TTL-based re-enrichment to the ledger: store `last_enriched`, `next_enrich_after`, analyzer status, and summary fields.
8. Make the Markdown tables deterministic Python output; pass rendered tables to Hermes instead of asking it to produce all table formatting.
9. Add a validation pass after Hermes prose: reject malformed tables, identifiers not present in evidence JSON, arithmetic drift, own-infra as attacker, and fake sensors.
10. Add a “Recommended Actions” section generated from deterministic rules: review, enrich, block candidate, hunt query, detection idea, or no action.
11. Build a weekly report from the same evidence store: trends, clusters, ATT&CK mappings, infrastructure reuse, collection gaps.
12. Only after the above, consider a reviewed write path into OpenCTI/MISP using separate writer credentials and deterministic STIX objects.
```
# CTI Hermes Sanity Check And Gap Analysis — 2026-08-03

## 1. Sanity Check

The current state is coherent for a defensive CTI lab pipeline: deterministic Python collects and calculates, IntelOwl enriches, MISP warninglists protect quota, OpenCTI is read-only, Hermes writes prose under a locked-down `rawingest` profile, and reports stay local. That is the right direction.

The biggest mismatch is documentation drift. [notes/architecture.md](/Users/darrellmiller/Documents/cti_hermes/notes/architecture.md:70) and [notes/intelowl.md](/Users/darrellmiller/Documents/cti_hermes/notes/intelowl.md:144) still point toward IntelOwl connectors writing into MISP/OpenCTI, but the actual current operating model is pull-only with connectors disabled. Treat the pull-only rule as authoritative and update the docs so the next assistant does not “complete” a now-forbidden write path.

Things that look right but are not quite right:

- The OpenCTI read-only account is good, and verified write denial is important. Keep it that way until STIX objects are deterministic, validated, reviewed, and written by a separate service account.
- T-Pot ES without auth is acceptable only for this internal PoC. It is still the largest blast radius because the agent host can query broad raw attacker-controlled data.
- IntelOwl pull-only is coherent, but the report only joins the latest submissions file, not necessarily the correct enrichment set for the report window. [src/daily_brief.py](/Users/darrellmiller/Documents/cti_hermes/src/daily_brief.py:142)
- The enrichment ledger prevents quota burn, but because it records an IOC once forever, reputation, ASN ownership, pulse membership, VT detections, and MISP context all go stale. [src/enrich_iocs.py](/Users/darrellmiller/Documents/cti_hermes/src/enrich_iocs.py:152)
- The top-IP enrichment selector is volume-biased. It does not prioritize new IPs, new ASNs, new hashes, new credential strings, or behavior changes. [src/enrich_iocs.py](/Users/darrellmiller/Documents/cti_hermes/src/enrich_iocs.py:89)
- `invalidJSONResponse` and `contentGenerationError` are still treated as sensor values in aggregation output unless filtered or remapped. The report warns “unknown,” but the pipeline should classify them as Galah failure artifacts, not sensors.
- The latest report still shows `76.165.200.190` as a top attacker while later enrichment says it was excluded as own infrastructure. That is confusing and materially misleading. [notes/reports/2026-08-03-daily-brief.md](/Users/darrellmiller/Documents/cti_hermes/notes/reports/2026-08-03-daily-brief.md:41)

## 2. Report Quality

As a CTI consumer, I would not yet use the daily brief for decisions. It is a telemetry summary with enrichment snippets, not an intelligence product.

Major weaknesses:

- It leads with volume, not change. Your own finding that only 11 of the top 200 IPs are new, and that `170.101.101.98` is both #1 and new, is more important than a 3.6% event increase.
- It ignores high-value Cowrie behavior: 1760 `command.input` events and 272 successful logins/day. That is closer to adversary tradecraft than P0f/Suricata volume.
- It treats top attackers as top event generators. That overweights monitoring noise and underweights hands-on-keyboard-ish behavior, successful auth, payload retrieval, commands, malware staging, and new infrastructure.
- It includes polluted sensor types in the main volume and top attacker tables. [notes/reports/2026-08-03-daily-brief.md](/Users/darrellmiller/Documents/cti_hermes/notes/reports/2026-08-03-daily-brief.md:29)
- The Markdown table is malformed, which is small mechanically but costly for trust. [notes/reports/2026-08-03-daily-brief.md](/Users/darrellmiller/Documents/cti_hermes/notes/reports/2026-08-03-daily-brief.md:15)
- Enrichment is over-interpreted. AbuseIPDB/VT/OTX hits say “known bad on the internet,” not “important in this collection.” The interesting question is what changed locally.
- The malware section is vague and partially incoherent. It lists hashes and reputation but does not say source sensor, delivery path, filename, URL, session linkage, architecture, family guess, or whether the hash is new locally.
- The CVE section is too thin. A Suricata CVE hit four times is a lead, not a finding. It needs signature, source/destination, request evidence, affected honeypot, and confidence.
- There are no recommended actions: no block candidates, hunt queries, Sigma/YARA ideas, OpenCTI objects to review, or “do not action” notes.
- There is no collection health section: which sensors produced useful activity, which produced only monitoring noise, which fields are unreliable, and what data was excluded.

## 3. Analytic Tradecraft Gaps

The core tradecraft gap is absence of “so what changed?” logic.

Needed analytic layers:

- Baselines: compare current 24h against prior 7/30/35 days for IPs, ASNs, countries, ports, sensors, usernames, passwords, commands, URLs, hashes, Suricata signatures, and CVEs.
- Novelty scoring: new source IP, new ASN, new CIDR, first-seen credential, first-seen command, first-seen hash, rare sensor combination, and sudden reappearance after dormancy.
- Behavior-first clustering: group by session behavior, not IOC reputation. Example clusters: SSH brute force with successful login, post-login command execution, web exploit probing, malware download, scanner-only noise.
- Cowrie session reconstruction: successful login -> commands -> downloaded URLs -> hashes -> outbound callbacks. This should be a top report section.
- ATT&CK mapping from behavior only. Credential attempts, successful auth, shell commands, wget/curl downloaders, persistence attempts, and discovery commands can map with rationale; IP reputation cannot.
- Infrastructure analysis: ASN/provider, rDNS, Shodan open services, datacenter/VPN annotation, co-occurrence across sensors, and repeat infrastructure over 35 days.
- Confidence discipline: every finding should have evidence, confidence, and an explicit “why this matters.”
- Source reliability: distinguish local honeypot observation, MISP warninglist context, OTX pulse membership, VT detections, AbuseIPDB reports, Shodan observations, and operator-owned exclusions.
- Decay and re-enrichment: reputation and context need TTLs by observable class, not a permanent seen ledger.
- Negative findings: explicitly say when activity is commodity scan noise, when not to block, when enrichment is stale, and when evidence is insufficient.

## 4. Opportunities Ranked By Value/Effort

| Rank | Opportunity | Value | Effort | Notes |
|---:|---|---|---|---|
| 1 | Add novelty/trend features to `daily_brief.py` using 35-day ES retention | Very high | Low-medium | This immediately fixes the volume bias. |
| 2 | Add Cowrie session analytics: successful logins, commands, URLs, hashes | Very high | Medium | Most useful tradecraft currently ignored. |
| 3 | Filter/remap Galah LLM failure values out of `type.keyword` sensor summaries | High | Low | Prevents fake sensors from polluting reports. |
| 4 | Split top activity into `top_volume`, `top_new`, `top_successful_auth`, `top_payload`, `top_enriched_bad` | High | Low-medium | Makes the report decision-friendly. |
| 5 | Add enrichment TTLs and re-enrichment policy | High | Low-medium | IPs perhaps 7 days, hashes 30 days, high-interest IOCs shorter. |
| 6 | Generate deterministic report tables and let Hermes write only summaries | High | Medium | Avoids malformed Markdown and invented claims. |
| 7 | Use RTX 5080 for structured extraction/classification of Cowrie commands and Galah web paths | Medium-high | Medium | Keep output schema-validated; no tools. |
| 8 | Use A6000 pending host for local embedding and clustering over 35-day sessions | Medium-high | Medium | Cluster commands, URLs, payloads, and signatures. |
| 9 | Add weekly analytic product with ATT&CK heatmap and infrastructure clusters | Medium-high | Medium | Better home for trend/campaign analysis. |
| 10 | Use OpenCTI as curated read model only until review queue exists | Medium | Medium | Keep pull-only now; later write only reviewed STIX. |
| 11 | Mine existing `tsec-*` indices before duplicating feed work | Medium | Low-medium | Existing GTI/OTX/AbuseIPDB/sandbox/llm-calls pipeline is an asset. |
| 12 | Add CrowdStrike/GTI/OTX context as enrichment fields, not prose-only claims | Medium | Medium | Make provider evidence auditable. |

## 5. Ordered Next Steps

1. Update architecture and IntelOwl notes to state the current rule: IntelOwl connectors disabled, pull-only, no writes to MISP/OpenCTI.
2. Fix the report’s own-infra handling so operator-owned IPs are excluded or clearly separated from attacker rankings.
3. Filter or remap `invalidJSONResponse` and `contentGenerationError` before sensor aggregation.
4. Add 35-day first-seen/last-seen counts for top IPs, hashes, usernames, passwords, commands, CVEs, and signatures.
5. Replace the single “Top Attackers” section with ranked sections for volume, novelty, successful login activity, command activity, payload/hash activity, and enriched high-confidence IOCs.
6. Add Cowrie analytics: successful logins, `command.input`, command sequences, URLs, downloaded hashes, and per-session summaries.
7. Add TTL-based re-enrichment to the ledger: store `last_enriched`, `next_enrich_after`, analyzer status, and summary fields.
8. Make the Markdown tables deterministic Python output; pass rendered tables to Hermes instead of asking it to produce all table formatting.
9. Add a validation pass after Hermes prose: reject malformed tables, identifiers not present in evidence JSON, arithmetic drift, own-infra as attacker, and fake sensors.
10. Add a “Recommended Actions” section generated from deterministic rules: review, enrich, block candidate, hunt query, detection idea, or no action.
11. Build a weekly report from the same evidence store: trends, clusters, ATT&CK mappings, infrastructure reuse, collection gaps.
12. Only after the above, consider a reviewed write path into OpenCTI/MISP using separate writer credentials and deterministic STIX objects.
