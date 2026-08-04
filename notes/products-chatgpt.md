# Product design — ChatGPT/Codex independent proposal (2026-08-04)

## 1. Intelligence Products

### Daily Operator Brief
**Audience:** operator only.  
**Length:** 1-2 pages, ideally under 900 words.  
**Purpose:** decide what needs attention today.

**Sections:**
1. **System Health**
   - Sensor uptime, ingest volume, parser failures, enrichment coverage, sandbox backlog, feed export status.
   - Delta from 7-day baseline.
2. **Finding Changes Since Yesterday**
   - New findings.
   - Resurfaced findings.
   - Escalated findings.
   - Quieted findings.
3. **Top Active Findings**
   - 5-10 items max.
   - Stable finding ID, title, status, priority, affected sensor/persona, first_seen, last_seen, evidence counts.
4. **Actions Needed**
   - Triage, suppression review, partner notification candidate, collection gap, enrichment failure.
5. **Watch Queue**
   - Reputation-blind clusters, coordinated ASN behavior, sector-specific targeting, malware awaiting sandbox result.

**Must include:** registry deltas, priority changes, operational anomalies, suppressed-count summary.

**Must not include:** long prose, raw IOC dumps, every port/protocol spike, repeated findings with no meaningful change.

**Derived from registry:** compare `last_seen`, `status`, `priority`, `evidence_count`, `affected_sensors`, `suppression_state`, and `last_reported_daily_at`. Daily prose should explain only changed or high-priority registry entries.

---

### Weekly Operator Brief
**Audience:** operator only.  
**Length:** 3-5 pages.  
**Purpose:** understand campaign movement and decide what deserves deeper analysis.

**Sections:**
1. **Executive Snapshot**
   - Major changes, notable campaigns, system health trend.
2. **Registry Movement**
   - New / active / escalated / quiet / resurfaced counts.
   - Priority distribution.
3. **Campaign and Cluster Review**
   - Cowrie TTP clusters.
   - Cross-sector differentials.
   - Coordinated ASN campaigns.
   - Reputation-blind queue.
4. **Malware and Tooling**
   - New samples, families, sandbox verdicts, repeated infrastructure.
5. **Sector Targeting**
   - Petrochemical, medtech, remote management, VoIP.
   - What was unique to a sector versus global noise.
6. **Suppressions and False-Positive Hygiene**
   - Newly suppressed patterns.
   - Suppressions nearing expiry.
7. **Recommended Work**
   - Promote to external report candidate.
   - Create OpenCTI candidate.
   - Export candidate.
   - Needs validation.

**Must include:** trend interpretation, registry state transitions, evidence maturity.

**Must not include:** partner-facing claims, unattributed actor naming, raw logs, sensitive sensor details.

**Derived from registry:** aggregate entries by week, status transitions, priority model, sectors, TTPs, ASN/country, confidence, and validation state.

---

### Monthly Partner Report
**Audience:** vetted external partners.  
**Length:** 5-8 pages.  
**Purpose:** share validated, useful intelligence without exposing collection posture.

**Sections:**
1. **Summary of Observed Threat Activity**
2. **Validated Campaigns or Clusters**
3. **Sector-Specific Observations**
4. **TTPs and Behavioral Patterns**
5. **Selected Infrastructure**
6. **Defensive Relevance**
7. **Confidence and Caveats**
8. **Appendix: Curated Indicators**

**Must include:** only reviewed findings marked `external_ok=true`; sanitized evidence; confidence labels; time bounds; observed behavior; recommended detection logic where possible.

**Must not include:** sensor names, exact honeypot configuration, lure design, collection volumes by site if revealing, raw attacker commands unless sanitized, unvalidated attribution, single-hit IPs, private notes, enrichment API results that cannot be redistributed.

**Derived from registry:** findings with status `active`, `escalated`, or recently `quiet`; priority above threshold; validated; not suppressed; partner-distribution approved.

---

### Quarterly and 6-Month Partner Reports
Treat these as strategic versions of the monthly report, not longer IOC dumps.

**Audience:** vetted partners, leadership, trusted CTI peers.  
**Length:** quarterly 10-15 pages; 6-month 15-25 pages.

**Sections:**
1. **Key Judgments**
2. **Threat Landscape Trends**
3. **Campaign Evolution**
4. **Sector Targeting Over Time**
5. **TTP Drift**
6. **Infrastructure Reuse**
7. **Malware and Tooling Trends**
8. **Defensive Opportunities**
9. **Methodology and Confidence**
10. **Curated Appendices**

**Must include:** longitudinal findings, not daily noise. Show what changed across time: new targeting, repeated ASNs, tooling changes, protocol shifts, resurfacing clusters.

**Must not include:** operationally sensitive collection details, full database extracts, partner-specific implications unless agreed, weak claims inflated by volume.

**Derived from registry:** longitudinal rollups over `first_seen`, `last_seen`, `status_history`, `priority_history`, `sector_scope`, `campaign_id`, `ttp_set`, and external-review flags.

---

## 2. External Publishing Risks and Mandatory Controls

Specific dangers:

- **Collection exposure:** reports can reveal honeypot personas, emulated services, geographic placement, detection gaps, and what the operator notices.
- **Attacker feedback loop:** adversaries can read reports and change behavior.
- **False attribution:** honeynet data shows interaction with decoys, not necessarily victimization or intent.
- **Poisoned evidence:** attackers can plant misleading commands, hostnames, payload names, comments, or fake flags.
- **Collateral damage:** publishing IPs can harm compromised third parties, NAT gateways, VPN exits, universities, or cloud customers.
- **Redistribution violations:** MaxMind, AbuseIPDB, GTI, FireHOL, sandbox, or commercial enrichment terms may limit sharing.
- **Partner over-trust:** recipients may block aggressively based on low-confidence honeypot-only observations.
- **Legal/privacy issues:** logs may contain credentials, personal data, or third-party secrets typed by attackers.
- **Operational reputation risk:** bad external reporting damages trust quickly.

Mandatory controls:

- External-release flag per finding.
- Human review before release.
- TLP marking on every report and object.
- Confidence score and evidence basis.
- Sanitization of raw commands, credentials, URLs with tokens, malware configs, and sensor identifiers.
- Minimum evidence thresholds by object type.
- Legal/licensing review for enriched fields.
- Partner distribution list control.
- Watermarked report versions or recipient-specific tracking.
- Retention of evidence internally for audit.
- Clear caveat: honeynet observation, not confirmed victim telemetry.
- Separate internal and external schemas/views.

---

## 3. Additive OpenCTI and OTX Contributions

The additive value is not “IP bad.” It is **behavior + targeting + time-bounded campaign context**.

### OpenCTI

Use STIX objects such as:

- **Observed Data**
  - Raw but normalized honeynet observations: IP, port, protocol, command, timestamp, sensor sector.
  - Confidence: high for “we observed this,” low/moderate for interpretation.

- **Indicator**
  - Only when an observable meets a detection-worthy threshold.
  - Example: infrastructure repeatedly performing LDAP/ARD probes only against petrochemical persona.
  - Include pattern, valid_from, valid_until, confidence, labels.

- **Intrusion Set or Campaign**
  - Use **Campaign** for clustered activity like the Croatian ASN petrochemical-only activity.
  - Avoid Intrusion Set unless there is strong external corroboration.

- **Malware**
  - RedTail samples, hashes, family name, sandbox behavior.
  - Confidence depends on static/sandbox/family validation.

- **Tool**
  - Reused scanners, brute-force tools, exploit kits, SSH automation.

- **Attack Pattern**
  - ATT&CK techniques selected only from the validated menu.
  - Relationship: campaign `uses` attack-pattern.

- **Infrastructure**
  - Hosting ASN, VPS ranges, C2 endpoints, download servers.
  - Use carefully; do not equate every source IP with attacker-controlled infrastructure.

- **Sighting**
  - Best object for recurring observations.
  - Link indicators/campaigns/malware to sightings over time.

- **Report**
  - Monthly/quarterly partner reports as STIX Reports linking the above.

Confidence handling:

- Separate **observation confidence** from **analytic confidence**.
- Honeynet event happened: high.
- Same operator controls all IPs: low unless supported.
- Campaign clustering: moderate if deterministic criteria are met.
- Attribution to named actor: default prohibited unless externally validated.

### OTX

OTX should receive curated pulses, not bulk exports.

Good OTX contributions:

- Malware hashes with behavior summary.
- Infrastructure clusters with time bounds.
- Targeting notes: “observed exclusively against petrochemical-themed honeypot services.”
- ATT&CK mappings.
- Detection ideas.
- Confidence and caveats.
- Expiry guidance.

Avoid:

- One-off scanner IPs.
- Full daily IP lists.
- Anything sourced primarily from AbuseIPDB/GTI/OTX itself.
- Unreviewed LLM-generated summaries.

---

## 4. Preconditions for Safe Write Paths

Before enabling writes to OpenCTI or OTX:

1. Findings registry exists and is authoritative.
2. Every exportable item has stable ID, evidence, confidence, status, and owner/reviewer.
3. Suppression system is active.
4. External-sharing policy is encoded, not just remembered.
5. Data license checks are implemented.
6. Raw honeypot artifacts are sanitized.
7. LLM prose cannot create facts; it can only summarize deterministic fields.
8. Export jobs are dry-run first.
9. OpenCTI writes go to a staging workspace or marking-definition-restricted collection first.
10. OTX publishing requires manual approval.
11. All outbound writes are auditable and reversible where the platform allows.
12. There is a denylist for sensitive observables, partner names, sensor identities, and known benign infrastructure.
13. Confidence thresholds differ by destination: OpenCTI can accept lower-confidence internal sightings; OTX should require higher-confidence validated packages.

---

## 5. Sequencing

1. **Build the findings registry**
   - Stable IDs, status transitions, priority, suppressions, evidence links.

2. **Refactor daily and weekly briefs around registry deltas**
   - Stop reporting stateless snapshots.

3. **Add external-review fields**
   - `external_ok`, `tlp`, `reviewer`, `reviewed_at`, `sharing_caveats`, `license_clear`.

4. **Create internal OpenCTI export dry-run**
   - Generate STIX bundles to disk only.
   - Validate objects, relationships, confidence, markings.

5. **Build partner-report generator**
   - Monthly first, then quarterly and 6-month rollups.

6. **Enable OpenCTI staging writes**
   - Internal only, restricted marking, no partner sync.

7. **Add OTX pulse draft generation**
   - Draft only, human approval required.

8. **Enable controlled production writes**
   - OpenCTI first.
   - OTX last, only for curated high-confidence intelligence.
