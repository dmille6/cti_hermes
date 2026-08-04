# ChatGPT/Codex strategic review — 2026-08-04

## 1. Overall Approach

Yes, the approach is right: **do not duplicate the tsec pipeline; build analytic interpretation on top of it.** The read-only posture is also right for now. The deterministic-facts / LLM-prose split is the most important architectural decision you made, and it should remain non-negotiable.

Where I would push back hardest: **you are building reports before proving a reader workflow exists.** Three separate markdown outputs with no lifecycle, triage state, suppression, alerting, or continuity means the system can be technically correct and still operationally unused.

The platform is currently closer to “daily CTI observability” than “defensive CTI operations.” That is not bad, but it should be named clearly.

## 2. Ranked Concerns by Real Risk

1. **(a) Nobody has read the reports yet**
   Highest risk. If the operator does not consume, trust, or act on the reports, everything else is premature. Usage beats sophistication.

2. **(b) No persistence of findings**
   Very high risk. Without continuity, RedTail and the Croatian campaign are anecdotes, not investigations. You need to know first seen, last seen, still active, resurged, expanded, quieted, or escalated.

3. **(e) No alerting**
   High risk, but only after persistence. Alerting on stateless snapshots creates noise. Alerting on persisted finding state creates signal.

4. **(d) Findings are not linked across reports**
   High risk. The same actor, ASN, IP, malware, credential pattern, command cluster, or Suricata behavior should converge into one finding. Otherwise the user has to do the correlation manually.

5. **(c) No evaluation harness**
   Medium-high risk. Important because LLM prose can drift and deterministic tables can regress. But it is not the first thing unless someone is already consuming the reports.

6. **(h) No prompt-injection regression corpus**
   Medium risk. Worth doing, especially because honeypot data is adversarial text. But your deterministic boundary already reduces the blast radius.

7. **(f) Insights die in markdown**
   Medium risk. This matters, but markdown is acceptable as a transitional artifact if you add finding state and alerting. Do not rush writes into external CTI systems.

8. **(g) OpenCTI MCP unused**
   Lowest risk. This is easy to over-weight because it feels like “integration maturity.” But premature OpenCTI integration could create bad objects, noisy observables, or misleading confidence. Pull-only OpenCTI lookups may be useful later; writes should wait.

## 3. Single Highest-Value Next Thing

Build a **persistent finding registry**.

Not a full case-management system. A small local SQLite-backed layer is enough:

- `finding_id`
- `finding_type`
- title
- deterministic evidence
- related IPs / ASNs / malware / command clusters / sectors / signatures
- first_seen
- last_seen
- current_status: `new`, `active`, `continuing`, `quiet`, `resurfaced`
- severity / priority
- confidence
- report links
- analyst notes or disposition, even if manual

Then have the three reporters emit candidate findings into this registry instead of only producing independent markdown tables.

Why this first: it unlocks almost everything else. Once findings persist, you can alert only on meaningful state transitions, merge RedTail evidence across Cowrie/daily/malware views, track whether Croatian LDAP/ARD activity is ongoing, and produce a single daily “what changed” brief instead of three static reports.

The best next report is probably not another reporter. It is a **daily findings delta**:

- New findings
- Findings still active
- Findings that escalated
- Findings that went quiet
- Findings that resurfaced
- Findings needing human review

## 4. What Makes This Genuinely Good

A competent project summarizes honeypot telemetry.

A good project produces **defensible, persistent, human-actionable CTI findings**.

The jump happens when the system can say:

> “This campaign began on 2026-08-03, remains active as of 2026-08-04, is still sector-exclusive to petrochemical, has no reputation coverage, expanded from 24 to 31 hosts in the same ASN, and now overlaps with credential attempts seen in Cowrie.”

That is operational intelligence. It has continuity, evidence, uncertainty, and decision value.

The other thing that would make it good: a feedback loop. Even a crude one.

- useful / not useful
- true positive / benign / already known
- suppress / watch / escalate
- analyst note

Without feedback, you cannot tell whether you are building intelligence or ornate telemetry.

## 5. Structurally Missing

You are missing a **priority model**.

Right now you have strong ingredients: novelty, sector exclusivity, volume, reputation gaps, coordinated ASN behavior, command clusters, malware, credentials. But you need an explicit deterministic scoring/ranking model that answers:

> “What should a human look at first, and why?”

It should be simple and inspectable. No ML needed. Example factors:

- sector-exclusive activity
- no reputation coverage
- multi-host coordination
- novelty versus 30-day baseline
- persistence across days
- malware observed
- credential harvesting or reuse
- ATT&CK relevance
- targeting sensitive emulated services
- expansion in entities, sectors, or techniques

Also missing: **negative controls and suppressions**. Some things will be noisy, repetitive, or known-good from the operator’s perspective. If the system cannot remember “do not keep telling me this,” daily reporting will decay.

Final opinion: do not build OpenCTI writes, more LLM sophistication, or more report types next. Build the finding registry, state transitions, and one consolidated daily findings delta. Then put alerting on top of that.
