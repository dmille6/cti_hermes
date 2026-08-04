# ChatGPT/Codex analysis with direct access to the cti1 platform docs (2026-08-04)

## 1. Real Current Gaps

The gap is not enrichment coverage. The platform’s own verdict is explicit: **collection is strong, correctness and sharing are weak**. `PLATFORM_EVALUATION_2026-07-28.md` gives collection `A-`, enrichment breadth `B+`, but sharing `D`, silent failure/error handling `D`, tests/CI `F`, observability `D+`.

Actual gaps:

- **Silent correctness failure.** `V2_CORE_DESIGN.md` lists 11 measured silent failures; the evaluation adds more. Healthchecks are mostly process-alive, not correctness-alive.
- **Active data-loss bugs.** `REMEDIATION_ROADMAP_2026-07-28.md` P0 names Suricata cursor advancement, GTI Livehunt “seen before write confirmed,” silent `except: pass`, and `gti-export` dead non-IP exports.
- **Parser output discarded downstream.** The correlator reads only a tiny whitelist from rich parser `extended` fields. `ip_reputation`, nested Heralding/Dionaea creds, Adbhoney C2 URLs, SMTP/SIP/HL7/ICS detail are parsed and then dropped (`PLATFORM_EVALUATION`, Q6; `REMEDIATION_ROADMAP`, P0-1).
- **Sharing is mostly not happening.** Blocklist feed inactive, MISP export org-only, external PDF path not used, outbound gates inconsistent, TLP ceilings missing (`PLATFORM_EVALUATION`, Q4; `REMEDIATION_ROADMAP`, P1/P3).
- **Sensor identity leakage was a real security failure.** `SENSOR_IDENTITY_DISCLOSURE.md` says sensor identity is topology, not intel; aliases/hostnames leaked through names, descriptions, labels, and notes.
- **No durable finding lifecycle.** Existing reports/backlogs exist, but not a compact reviewed finding state with first/last seen, suppression, escalation, and continuity.
- **Docs/config drift.** `PROJECT_OVERVIEW.md` is representative/stale in places; `REMEDIATION_ROADMAP` P4 explicitly calls out stale docs and contradictions.

## 2. cti_hermes: Keep, Merge, Delete

**Genuinely valuable:**

- `src/findings.py`: keep. Stable finding IDs, first/last seen, status transitions, suppressions, provenance separation, confidence ceilings, poisoning-risk caps. This addresses a real platform gap.
- `src/daily_status.py`: keep, but make it the front door. Short health + findings delta beats another long report.
- Parts of `sector_diff.py`: keep as a findings emitter for sector-exclusive, reputation-blind, coordinated-ASN, and expansion findings. This complements persona sensors, but only if it becomes persistent findings, not another Markdown slab.
- Parts of `cowrie_ttp.py`: keep only for **sequence-level behavior gaps**: distinct-command outliers, full-session reconstruction, and observed-command ATT&CK mapping from a controlled menu. This aligns with `OPEN_FINDINGS.md` high-volume actor problem and `REMEDIATION_ROADMAP` P3-7.

**Duplicative:**

- General daily brief in `daily_brief.py`: duplicates tsec daily/weekly/monthly digests and premium reports. It also already shows LLM drift and mediocre recommendations. Retire as primary output.
- Campaign clustering in `cowrie_ttp.py`: overlaps existing `CAMPAIGN_CLUSTERER_HANDOFF.md` behavior clustering. Keep only if it finds a specific blind spot the existing clusterer cannot.
- Sector/persona reporting: overlaps weekly/monthly persona attacker-pattern reports. Keep only the differential finding logic.

**Delete or freeze outright:**

- `src/enrich_iocs.py`: stop. It rebuilds enrichment fan-out on top of a platform that already has GTI/OTX/AbuseIPDB/Shodan/MISP-style connectors. Worse, `OPEN_FINDINGS.md` says the platform is feature-complete/refine-only.
- IntelOwl-as-enrichment architecture in `notes/architecture.md`: obsolete for this operator. Keep notes as historical, but do not build against it.
- Any plan to write to MISP/OpenCTI from cti_hermes. The platform already has write paths; cti_hermes should not become a second ungoverned publisher.

## 3. Best Role

**cti_hermes should become a read-only findings and verification sentinel for tsec.**

Not an enrichment layer. Not a replacement analyst platform. Not another report generator.

Its job: read ES/OpenCTI, produce persistent findings, detect deltas/escalations, expose silent correctness failures, and give the operator a short daily queue of what changed and what needs review.

## 4. Sequenced Plan

1. **Stop building enrichment.** Freeze IntelOwl submission and `enrich_iocs.py`.
2. **Make `findings.py` the center.** All analytics emit candidate findings, not standalone products.
3. **Replace daily reports with `daily_status.py`.** One short daily delta: health, new/escalated/resurfaced findings, high-priority unreviewed items.
4. **Convert `sector_diff.py` into emitters.** Findings: reputation-blind actor, coordinated ASN campaign, sector-exclusive spike, cross-sector expansion.
5. **Trim `cowrie_ttp.py`.** Keep full-session/high-volume detection and sequence ATT&CK. Drop generic cluster prose.
6. **Add correctness checks matching tsec roadmap.** Watch for P0/P1/P2 signals: connector freshness, output drops, public identity tokens, enrichment/export inactivity.
7. **Feed tsec remediation, not OpenCTI.** cti_hermes should produce operator tasks: “Suricata cursor risk still present,” “blocklist feed inactive,” “MISP distribution still org-only.”
8. **Only after that, add alerting.** Alert on finding state transitions and health failures, not raw event volume.

## 5. What You Got Wrong

You treated missing insight as missing enrichment. The docs make the opposite obvious.

The platform already has broad enrichment, personas, LLM classification, campaign clustering, reports, malware family tracking, MISP/OpenCTI plumbing, and sharing connectors. The real failure is that high-value work silently drops, gets flattened into prose, fails to ship, leaks topology, or dies in oversized reports.

You also overvalued “more reports.” The operator does not need another 4,000-word daily artifact. They need a short, persistent, suppressible findings queue.

Bluntly: **cti_hermes was headed toward becoming a duplicate mini-platform. Its defensible future is as the read-only conscience and findings layer for the existing one.**
