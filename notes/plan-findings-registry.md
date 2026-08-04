# Forward plan: from reports to findings (2026-08-04)

Agreed between Claude and ChatGPT/Codex. Full review:
`notes/reviews/2026-08-04-chatgpt-codex-strategic.md`.

## Verdict on the approach

**Right, and worth continuing.** Not duplicating the tsec pipeline was
correct. Read-only is correct for now. The deterministic-facts / LLM-prose
split is the single best decision in the project and stays non-negotiable —
it has caught fabricated table figures, invented ATT&CK ids, and a corrupted
cluster fingerprint.

**The hardest pushback, which both of us reached independently:** we built
reports before proving anyone would read them. Codex's phrasing — the system
is currently *"daily CTI observability"*, not *"defensive CTI operations"*.

### Measured evidence for that concern

| | |
|---|---|
| Daily output across 3 reports | **496 lines, 4,299 words, 241 table rows** |
| Evidence snapshots retained | **1 per report type** (same-day reruns overwrite) |
| Can we say "is RedTail still active?" | **No** — each run is a stateless snapshot |

4,300 words a day is not a product anyone sustains reading. And with no
persistence, RedTail and the Croatian ASN campaign are anecdotes rather than
investigations.

## Concerns ranked by real risk (Codex's ranking, which I accept)

1. **Nobody has read the reports** — highest. Usage beats sophistication.
2. **No persistence of findings** — very high. Unlocks everything else.
3. **No alerting** — high, but *only after* persistence. Alerting on
   stateless snapshots manufactures noise.
4. **Findings not linked across reports** — high. The same actor appears in
   Cowrie clusters, sector concentration, and malware views with no join.
5. **No evaluation harness** — medium-high.
6. **No prompt-injection regression corpus** — medium. The deterministic
   boundary already limits blast radius.
7. **Insights die in markdown** — medium. Acceptable transitional state.
8. **OpenCTI MCP unused** — **lowest.** I was over-weighting this; it feels
   like integration maturity but premature writes would create bad objects.
   Keep it for interactive lookups.

## The next thing to build: a persistent finding registry

A small SQLite layer on the VM. Not case management.

```
finding_id            stable, deterministic (hash of type + key evidence)
finding_type          asn_campaign | command_cluster | reputation_blind_actor |
                      credential_pattern | malware_sighting
title                 human-readable
evidence              JSON: the deterministic facts that produced it
related               IPs, ASNs, sectors, hashes, command fingerprints
first_seen / last_seen
status                new | active | continuing | quiet | resurfaced | expanded
priority              from the scoring model below
confidence
disposition           unreviewed | true_positive | benign | known | suppressed
notes                 analyst free text
```

The three reporters stop being the product and become **emitters** of
candidate findings. The product becomes a **daily findings delta**:

- New findings
- Still active
- **Escalated** (more hosts, more sectors, new techniques)
- Went quiet
- Resurfaced
- Needing human review

That is short — the thing a person will actually read every morning.

## Two things Codex added that I had missed

### A priority model
An explicit, inspectable, deterministic score answering *"what should a human
look at first, and why?"* No ML. Factors already computed:

sector exclusivity · absent reputation coverage · multi-host coordination ·
novelty vs 30-day baseline · **persistence across days** · malware observed ·
credential harvesting · ATT&CK relevance · expansion in hosts/sectors/techniques

### Suppressions / negative controls
The system must be able to remember *"stop telling me this."* Without it,
daily reporting decays into noise and gets ignored. This is what turns the
disposition field from bookkeeping into a feedback loop.

## What "good" looks like

A competent project summarises honeypot telemetry. A good one produces
defensible, persistent, actionable findings. The jump is being able to say:

> "This campaign began 2026-08-03, remains active as of 2026-08-04, is still
> sector-exclusive to petrochemical, has no reputation coverage, expanded
> from 24 to 31 hosts in the same ASN, and now overlaps with credential
> attempts seen in Cowrie."

Continuity, evidence, uncertainty, decision value.

## Order of work

1. **Findings registry** (SQLite) + emit from the three existing reporters.
2. **Daily findings delta** as the single consolidated product; the three
   detailed reports become appendices/on-demand.
3. **Priority model** — deterministic scoring.
4. **Disposition + suppression** — the feedback loop.
5. **Alerting** on state transitions only (new / escalated / resurfaced).
6. Then evaluation harness, then injection corpus.

Explicitly **not** next: OpenCTI writes, more LLM sophistication, more report
types.

## Open question for the operator

Before building: **will you read a daily brief, and in what form?** Email,
Signal/Telegram push, a file you open, a terminal command you run? The answer
changes what step 2 should produce. Building a delivery mechanism nobody opens
is the failure mode both reviewers flagged as the top risk.
