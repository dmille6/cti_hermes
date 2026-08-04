# Data expansion — Claude's answer (2026-08-04)

## First, a correction to the premise

We are not only looking at Cowrie. `sector_diff.py` already spans **every**
sensor — but only at *metadata* level (volume, source, port, geo, ASN,
reputation label, sensor identity). What is Cowrie-only is **behavioural**
analysis: sessions, commands, what an intruder actually did.

So the gap is not "other sensors are unread". It is: **we can say what
happened next only for SSH.**

## What is actually in the other sensors (verified by query)

| Sensor | Volume/day | Fields that matter |
|---|---|---|
| **Beelzebub** | 227k | `input`, `output`, `session`, `username`, `service`, `protocol` |
| **Heralding** | 494k | `username`, `password`, `proto`, `session_id` |
| **Galah** | 97k | `request.body`, `request.bodySha256`, full headers, User-Agent |
| **Sentrypeer** | 1.7k | `called_number`, `sip_method`, `sip_user_agent` |
| **ConPot** | 2.2k | `conpot_request`, `conpot_response`, `event_type` |
| Dicompot | 0 in 24h | (medical imaging — currently silent) |

## Priority order

**1. Beelzebub — do this first.** It has `input`, `output` and `session`:
structurally the *same shape as Cowrie*, at **2.3× the volume**, and being
LLM-backed it holds attackers in conversation longer, so sessions run deeper.
`cowrie_ttp.py` already does session reconstruction, normalisation, clustering
and ATT&CK mapping — this is mostly a matter of generalising the field names
and event vocabulary. **Largest analytic gain for the least new code.**

**2. Heralding — credential intelligence at scale.** 494k/day of
`username`/`password`/`proto` across many protocols. Unlocks:
- credential-reuse campaigns (same pairs across sectors and protocols)
- **sector-themed credential targeting** — PBX terms at VoIP, PACS/radiology
  terms at medtech, PLC/vendor terms at ICS. This is intent evidence that is
  hard to fake, because it requires knowing what the target should look like.
- cross-protocol spray patterns

**3. Galah — web exploitation.** `request.body` plus `bodySha256` means
payload bodies are already hashed for us. Gives CVE probing, webshell upload
attempts, admin-panel scanning, and User-Agent toolmarks. Pairs naturally
with the Suricata CVE signals we currently under-use.

**4. Sentrypeer — small but uniquely actionable.** `called_number` is
**toll-fraud intelligence**: premium-rate and international destinations
attackers try to dial. Almost nobody shares this, it is directly actionable
for a telecom partner, and the volume is trivial to process.

**Deprioritise:** Fatt and P0f as *finding sources* — they are fingerprint
enrichment that should strengthen clustering and confidence, not generate
findings of their own. ConPot/Dicompot/Medpot are analytically rich per event
but currently near-silent; wire them when they see traffic.

## The cross-source analysis this unlocks

The prize is **intent stratification** — separating an actor who sprays
everything from one who *knows what they have found*:

- An actor who runs generic SSH brute force everywhere but switches to
  DICOM/HL7 grammar **only** at the medical sensor is demonstrating target
  awareness. That is a qualitatively different threat from a scanner.
- **Protocol grammar is expensive to fake.** Speaking valid DICOM or SIP
  requires real knowledge; typing "hospital" into a shell does not. This
  makes sector-native protocol use one of our highest-integrity signals —
  precisely the opposite of the poisoning-prone string evidence.
- Credential themes cross-referenced with sector: does the actor bring
  PBX-specific credentials to the PBX?
- JA3/HASSH (Fatt) linking rotating IPs into one infrastructure cluster —
  defeats the novelty-gaming vector.
- Session → payload → sandbox verdict chains, by consuming tsec's malware
  vault rather than rebuilding it.

## What NOT to ingest

1. **Raw LLM honeypot transcripts as evidence.** Beelzebub and Galah generate
   *model* responses. Those are our own text, not attacker behaviour, and
   ingesting them as evidence would let us cite ourselves. Extract the
   attacker side and deterministic metadata only.
2. **Anything tsec already does** — malware collection, sandboxing,
   enrichment, feed export. Consume its outputs by hash and session id.
3. **Per-event findings.** A credential attempt is an observation, not a
   finding. At 494k/day, one-finding-per-event destroys the registry.
4. **P0f/Fatt as standalone findings** — enrichment only.

## What breaks at this scale

Today's registry assumes "interesting thing → finding". At 494k credential
events/day that collapses. Required changes:

- **Aggregation-first.** Findings must key on *campaign-level* identity
  (credential set + protocol + sector), never on individual events.
- **Saturation.** The 900,000th identical login attempt should increment a
  counter, not re-raise priority. Volume must saturate.
- **Per-type priority models.** One valid DICOM C-ECHO from a clean IP should
  outrank 50,000 generic SSH failures. A single global scoring function
  cannot express that.
- **Intent as a dimension separate from severity.** Sector-native protocol
  grammar raises *intent* even with no malware involved.
- **Evidence-weighted poisoning risk per field.** A parsed protocol operation
  is high-integrity; free-form web/LLM text is low. The current model scores
  poisoning per *finding*; it needs to be per *evidence field*.
- **Retention tiers** — raw stays in Elasticsearch, normalised observations in
  analytics tables, only durable findings in the registry.
