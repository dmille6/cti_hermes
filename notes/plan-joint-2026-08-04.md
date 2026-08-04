# Joint plan: what cti_hermes should become (2026-08-04)

Claude and ChatGPT, both now working from the **real** platform docs on cti1
(76 files). ChatGPT's full analysis:
`notes/reviews/2026-08-04-chatgpt-with-platform-access.md`.

## The verdict we both reached

> **cti_hermes should be the read-only findings and verification layer for
> tsec — not a second platform.**

## What the platform's own evaluation says

`PLATFORM_EVALUATION_2026-07-28.md` grades it:

| Area | Grade |
|---|---|
| Collection | A− |
| Enrichment breadth | B+ |
| **Sharing** | **D** |
| **Silent failure / error handling** | **D** |
| **Tests / CI** | **F** |
| **Observability** | **D+** |

Every session where I built collection or enrichment was work in the A−/B+
columns. The failing columns are correctness, observability and sharing —
and those are exactly what a findings registry with provenance, persistence
and health checks addresses.

## The three findings that decide the direction

**1. The canonical silent failure (`OPEN_FINDINGS.md`).**
For `207.56.16.112`, the hp-connector threat-note said **"5 commands"** while
ES held **30,575 (3,660 distinct)**. Nothing flagged the discrepancy — it was
caught "by luck eyeballing raw ES." A ~2h11m session at ~278 commands/minute
was reported as five.

That is the argument for the sentinel role in one example. *(Note: the
operator was explicitly NOT sold on a reconciliation-check connector; the
preferred angle was whole-population ranking so outliers self-announce.
Respect that — build noticing, not reconciliation.)*

**2. A decision pending since 2026-06-03 — which cti_hermes already answers.**
The open question was how to surface high-volume actors. The 80/20 on the
table: (a) a "Top 10 actors by distinct-command count" line so outliers
self-announce, (b) an on-demand `full_session_note.py <ip>`. Sizing: only
~0.5 genuinely-rich actors/day, so an always-on daily-pass connector was
judged over-engineered.

Our findings registry + deterministic priority **is** the generalised form of
(a), and it already ranks the whole population. This is the cleanest place
for cti_hermes to deliver value against a real, still-open operator question.

**3. Their documented biggest gap: payload capture from the LLM honeypots.**
`OPEN_FINDINGS.md` marks it ❌ **"biggest gap"** — Cowrie → vault works, but
**Beelzebub/Galah dropped payloads are never fetched**, so they are never
sandboxed, so the Malware SDO / hash / TTP chain never happens for those
sensors. Note Beelzebub is 227k events/day and Galah 97k.

**4. Parser output is parsed then discarded.** The correlator reads only a
small whitelist of `extended` fields, so `ip_reputation`, nested
Heralding/Dionaea credentials, Adbhoney C2 URLs, and SMTP/SIP/HL7/ICS detail
are extracted and thrown away (`PLATFORM_EVALUATION` Q6, `REMEDIATION_ROADMAP`
P0-1). The data I proposed "bringing in" is already parsed — it is being
dropped downstream, which is a much cheaper fix than new ingestion.

## Keep / merge / delete

**Keep — genuinely additive:**
- `findings.py` — persistent finding lifecycle with provenance separation,
  forgery-cost ceilings and poisoning caps. The platform has reports and a
  backlog but no durable reviewed finding state.
- `daily_status.py` — make it the front door. Short health + delta.
- `sector_diff.py` — **as an emitter only**: reputation-blind actor,
  coordinated ASN campaign, sector-exclusive spike, cross-sector expansion.
- `cowrie_ttp.py` — **trim to** high-volume/distinct-command outlier
  detection and observed-command ATT&CK. That directly serves the pending
  decision above.

**Duplicative — retire as primary output:**
- `daily_brief.py` — overlaps the existing daily/weekly/monthly digests and
  the premium PDF reports.
- Generic campaign clustering — `CAMPAIGN_CLUSTERER_HANDOFF.md` exists.
- Sector/persona reporting prose — weekly/monthly persona attacker-pattern
  auto-reports already exist.

**Delete / freeze:**
- `enrich_iocs.py` and the IntelOwl path. The platform is feature-complete on
  enrichment; this was the original mistake.
- Every plan for cti_hermes to write to MISP/OpenCTI. The platform already
  has governed write paths; a second publisher is a liability.

## Sequenced plan

1. **Freeze** `enrich_iocs.py` and IntelOwl. Mark `notes/architecture.md`
   historical.
2. **Registry becomes the centre.** All analytics emit candidate findings;
   nothing produces a standalone product.
3. **`daily_status.py` becomes the only daily artifact.** Retire
   `daily_brief.py`.
4. **Convert `sector_diff.py` to emitters.**
5. **Trim `cowrie_ttp.py`** to outlier + sequence ATT&CK; add the "top actors
   by distinct-command count" ranking that answers the June decision.
6. **Add correctness/health sentinels** aligned to the tsec roadmap:
   connector freshness, output-drop detection, enrichment/export inactivity,
   and public-identity token leakage (per `SENSOR_IDENTITY_DISCLOSURE.md`).
7. **Output operator tasks, not STIX.** "Blocklist feed still inactive",
   "MISP distribution still org-only", "Suricata cursor risk present".
8. **Alerting last**, on finding-state transitions and health failures only.

## Before any of it: verify which hive is authoritative

`CLAUDE.md` on cti1 names the hive as **99.18.26.20**; every cti_hermes
analytic queries **10.0.0.75 (`hivev2`)**. Until that is resolved, our numbers
may describe a different population than the platform's. **Highest-priority
open question.**

## What I got wrong

I treated missing insight as missing enrichment. The docs make the opposite
plain: the platform has enrichment, personas, LLM classification, campaign
clustering, reports, family tracking and OpenCTI plumbing. What it lacks is
**correctness discipline, observability and sharing** — and high-value work
silently dropping, being flattened into prose, or never shipping.

I also overvalued reports. The operator does not need another 4,000-word daily
artifact; they need a short, persistent, suppressible findings queue.
