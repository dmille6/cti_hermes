# Product design — Claude's independent proposal (2026-08-04)

Written before reading ChatGPT's answer, so the two can be compared honestly.

## The core idea

**One findings registry, five outputs.** Every product below is a *view* over
the same persisted findings at a different time horizon and trust level. If
the registry is right, the products are mostly formatting and filtering.

| Product | Audience | Horizon | Trust level |
|---|---|---|---|
| Daily brief | operator | 24 h delta | raw, unreviewed |
| Weekly brief | operator | 7 d rollup | raw, unreviewed |
| Monthly report | vetted partners | 30 d | **reviewed + sanitised** |
| Quarterly report | vetted partners | 90 d | reviewed + sanitised |
| 6-month report | vetted partners | 180 d | reviewed + sanitised |

---

## 1. Daily brief (you only)

**Job to be done:** in two minutes — is everything working, what changed,
what needs me today?

**Sections (in this order):**
1. **System health** — one line per subsystem, green/amber/red:
   sensor liveness (each site reporting in the last hour), ingest rate vs
   7-day mean, connector error count, enrichment coverage drift, last night's
   report jobs, LLM endpoint reachable, disk headroom.
2. **What changed** — findings that are `new`, `escalated`, or `resurfaced`.
   Nothing else. One line each, with priority score and a finding id.
3. **Needs your decision** — findings awaiting disposition, oldest first.
4. **Quiet** — one line: "N findings continuing, unchanged."

**Length: under 400 words. It should be nearly empty on a quiet day.**
"All sensors green · no new findings · 6 continuing" is a *good* daily brief.

**Must NOT contain:** unchanged findings restated, full tables, raw attacker
text, anything requiring scrolling. Detail lives in the existing three
reports, linked by finding id.

## 2. Weekly brief (you only)

**Job to be done:** in ten minutes — what are the trends, what is persisting,
what did I let slide?

**Sections:**
1. **Week over week** — volume, novelty rate, sector mix shifts.
2. **Findings lifecycle** — opened / escalated / went quiet / closed, with a
   sparkline-style count per day.
3. **Persistent campaigns** — anything active 3+ days, with trajectory
   (expanding / stable / fading) and host counts over time.
4. **Sector movement** — did an actor cross from one sector to another? That
   is the highest-signal event this platform can detect.
5. **Ageing** — findings unreviewed for more than 7 days.
6. **Collection health trend** — sensor uptime, Galah LLM failure rate,
   enrichment coverage, report job success.
7. **Suppression audit** — what got auto-suppressed this week. Guards against
   quietly muting something real.

**Length: ~1,000 words.**

## 3–5. Partner reports (monthly / quarterly / 6-month)

Same skeleton, different altitude:

- **Monthly — tactical.** Active campaigns, new TTPs, high-confidence IOCs
  with expiry dates.
- **Quarterly — analytic.** Sector targeting trends, actor behaviour
  evolution, ATT&CK coverage shifts, infrastructure reuse.
- **6-month — strategic.** Longitudinal: how the threat picture for these
  sectors changed, what emerged, what disappeared.

**Sections:**
1. TLP marking, period covered, named releaser, version.
2. Executive summary.
3. **Sector targeting overview — the differentiator.** No one else can say
   "actors behave differently against medtech-presenting hosts than against
   VoIP-presenting hosts."
4. Active campaigns: first seen, last seen, trajectory, host counts,
   concentration, confidence.
5. TTP analysis with ATT&CK, mapped from observed commands only.
6. IOCs — high-confidence only, each with confidence, first/last seen, and
   an explicit expiry.
7. **Collection methodology and limitations.** Essential for credibility, and
   it is where you say what the data cannot support.
8. Appendix: machine-readable STIX bundle.

**Length:** monthly ~2,000 words; quarterly ~4,000; 6-month ~6,000.

---

## What must NEVER leave the building

This is the part that matters most, because it is irreversible.

| Risk | Why it is serious |
|---|---|
| **Sensor burn** | Publishing sensor IPs, hostnames (`db4lamedtech`), exact counts or placement lets adversaries fingerprint and avoid your honeypots. That destroys the collection this whole platform depends on. **The single biggest risk.** |
| **Injection by proxy** | Attacker-controlled text in your report runs in a *partner's* tooling. Your prompt-injection problem becomes theirs. |
| **Third-party harm** | Most attacking IPs are themselves compromised victims. Publishing them as "malicious actors" without care harms innocents. |
| **Credential republication** | Attackers spray real breached credentials. Republishing them re-victimises the real owners. |
| **Contraband** | Honeypots capture uploaded files. Some may be illegal to redistribute. Publish hashes, never payloads. |
| **Victim disclosure** | Attacker commands and URLs frequently name *other* victims' infrastructure. |
| **Capability disclosure** | Saying precisely what you can and cannot see tells adversaries exactly how to evade you. |

**Mandatory controls before any external release:**
1. **Human review gate — non-negotiable**, with a rendered diff of exactly
   what will be published.
2. **Automated pre-publication scrubber**: homenet re-check, sensor
   identifier removal, credential redaction, payloads reduced to hashes,
   URL defanging, third-party host removal.
3. TLP marking and an explicit distribution list of vetted partners.
4. Confidence and methodology statement attached to every claim.
5. IOC expiry dates — stale indicators cause partner false positives.
6. Named releaser and a retained copy of exactly what was sent.

---

## What we can contribute to OpenCTI and OTX

**Not additive:** more IP indicators. Everyone has those, and your own tsec
pipeline already exports to GTI/OTX/AbuseIPDB. Adding volume adds noise.

**Genuinely additive, in priority order:**

1. **Sector-attributed targeting.** "This actor exclusively targets
   medtech-presenting hosts." Structurally impossible for a single-sector
   sensor or a commercial feed to produce. Highest value to defenders.
2. **Reputation-blind actors.** Actors *no* feed classifies — like the 24
   Croatian hosts. By definition this fills a gap in everyone's coverage.
3. **Command-sequence TTP clusters** with ATT&CK, from observed post-
   compromise behaviour rather than reputation.
4. **Coordinated ASN campaigns** as *infrastructure*, not loose IOCs.
5. **Negative findings.** "This looks alarming but is a known benign
   scanner." Rarely shared, disproportionately useful.

**STIX mapping:**

| Content | STIX object |
|---|---|
| Raw observation | `observed-data` + SCOs |
| "We saw X at time T on sensor class Y" | **`sighting`** — the honest primitive for honeypot data |
| Reusable detection pattern | `indicator`, only with analytic confidence, `valid_from` + `valid_until` |
| Observed behaviour | `attack-pattern` refs via `attackcti` — never free-form technique names |
| ASN campaign grouping | **`infrastructure`** — underused and exactly right here |
| Sustained coherent activity | `campaign`, only when registry persistence justifies it |
| Analyst assessment | `note` / `opinion` |
| Sector targeting | `targets` relationship to an `identity` with the sector |

Confidence must be derived **deterministically** from the priority model, not
written by the LLM. Deterministic external IDs for idempotent upsert.
`object_marking_refs` for TLP on every object.

## Before any write path is safe

1. Findings registry with disposition — only `true_positive`, human-reviewed
   findings are publishable.
2. Human approval gate with a diff.
3. A **separate low-privilege writer account** — not the current read-only
   one, and never the admin token.
4. **Zero LLM in the write path.** STIX is serialised deterministically.
5. Sanitiser and homenet re-check at write time, not just at analysis time.
6. Idempotent deterministic IDs so retries cannot pollute.
7. Retraction capability — know what you wrote and be able to withdraw it.
8. Volume caps and rate limits.
9. The prompt-injection regression corpus finally built and passing.

## Sequencing

1. **Findings registry** (agreed).
2. **System health checks** — needed by the daily brief anyway, and it is
   the part you will notice immediately if it breaks.
3. **Daily brief from the registry** — smallest product, proves the loop.
4. **Weekly** — cheap once the registry exists.
5. **Disposition and suppression** (CLI is fine) — the feedback loop.
6. **Sanitiser + monthly partner report**, with the human gate.
7. **STIX serialiser → OpenCTI write**, gated on all of the above.
8. **OTX sharing last** — it is the least reversible.
