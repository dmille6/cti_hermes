# Data expansion — ChatGPT/Codex answer (2026-08-04)

## 1. Priority Order

1. **Heralding**
   Highest value per effort. It is huge volume, credential-centric, multi-protocol, and structurally simple. It can immediately generalize the Cowrie credential analysis beyond SSH/Telnet into FTP, POP3, IMAP, SMTP, HTTP auth, MSSQL, etc. This gives attacker intent, protocol preference, sector targeting, and credential reuse without needing deep parsers.

2. **ConPot, Dicompot, Medpot, Sentrypeer**
   Treat these as one priority band: sector-specific intent sensors. They are lower volume than Heralding but analytically much richer because protocol choice itself is meaningful. DICOM, HL7, Modbus/S7/ICS, and SIP behavior are not interchangeable with generic internet scanning.

3. **Dionaea + tsec malware vault/sandbox/sightings**
   Do not duplicate tsec, but consume its outputs. Malware linkage is the bridge between network behavior and payload intent. This enables campaign clustering by delivered artifact, sandbox family, C2, dropped files, and sector-specific payload targeting.

4. **Beelzebub + Galah + Tanner**
   Web/LLM interaction content is valuable, but more expensive to normalize and more poisoning-prone. Ingest after deterministic schemas are clear. Focus on attacker requests, paths, payload classes, and toolmarks, not free-form LLM transcript semantics.

5. **Fatt + P0f**
   Useful as enrichment, not primary finding generators. JA3, HASSH, user-agent, OS fingerprint, and TLS/client traits should strengthen clustering and confidence, but rarely deserve standalone findings.

6. **Adbhoney, Ddospot, H0neytr4p, Mailoney**
   Ingest selectively once the above are stable. They are useful for niche campaign detection, but lower immediate return unless a sector-specific question demands them.

## 2. Top Sources: Extracts And Findings

### Heralding

Extract:

- `src_ip`, timestamp, sensor/sector, protocol, username, password, auth outcome
- credential pair normalization and password class
- protocol fanout per source
- sector fanout per source
- repeated credentials across protocols and sectors
- client banners where available

Finding types:

- `credential_reuse_campaign`: same credential set used across many sectors/protocols
- `protocol_specific_bruteforce`: focused brute force against one protocol
- `sector_credential_targeting`: credential themes aligned to sector, such as medical, admin, pbx, scada, vpn
- `reputation_blind_credential_actor`: high-volume or high-specificity credential activity from sources without bad reputation labels
- `cross_protocol_auth_spray`: same source rotates FTP/SMTP/IMAP/HTTP/etc.

### Sector-Specific Protocol Honeypots: ConPot, Dicompot, Medpot, Sentrypeer

Extract:

- protocol operation names, function codes, request paths/messages
- queried device identifiers, AE titles, HL7 message types, SIP methods, Modbus/S7 operations
- malformed versus valid protocol behavior
- authentication attempts where relevant
- command/read/write distinction
- source fanout across sector sensors
- protocol-specific rare operations

Finding types:

- `medical_protocol_probe`: DICOM/HL7-aware activity beyond port scanning
- `ics_function_probe`: Modbus/S7/industrial operation enumeration or write attempts
- `voip_abuse_campaign`: SIP registration, INVITE flooding, extension guessing, toll-fraud indicators
- `sector_native_actor`: source demonstrates real protocol grammar for a sector-specific service
- `dangerous_operation_attempt`: write/control operation against ICS or sensitive medical workflow protocol
- `sector_protocol_crossover`: same source uses sector-native protocols across unrelated verticals

### Dionaea + tsec Malware Outputs

Extract from tsec outputs only:

- malware hash, first/last sighting, source IP, delivery protocol, sensor/sector
- sandbox verdict, family, signatures, contacted domains/IPs, dropped files
- malware sighting counts and recurrence
- relationship to session/finding IDs
- payload URL, filename, MIME/type if already extracted by tsec

Finding types:

- `payload_reuse_campaign`: same hash delivered across sectors or protocols
- `sector_targeted_payload`: payload appears only or disproportionately in one sector
- `malware_backed_intrusion_attempt`: behavioral activity linked to confirmed malicious artifact
- `new_payload_from_low_rep_source`: novel or rare payload from source not already labeled bad
- `sandbox_family_sector_shift`: known family newly appearing against medical/ICS/VoIP sensors

### Beelzebub, Galah, Tanner

Extract:

- HTTP method, path, query keys, headers, user-agent
- normalized exploit class: traversal, RCE probe, shell upload, credential leak path, admin panel scan
- requested CVE/path/tool fingerprint
- payload hashes or normalized command strings
- LLM transcript metadata only: intent category, requested action, injected commands, not raw prose as evidence

Finding types:

- `web_exploit_campaign`
- `llm_honeypot_toolmark_cluster`
- `sector_web_admin_probe`
- `prompt_injection_or_interactive_attack`
- `web_to_payload_delivery_chain`

## 3. New Cross-Source Analysis

The major unlock is **actor intent stratification**.

Single sensors can say “this IP brute-forced SSH” or “this IP sent a DICOM request.” Cross-source analysis can say:

- This actor performs generic credential spraying everywhere, but switches to DICOM/HL7 only on medical-sector sensors.
- This ASN runs broad scanning, but only delivers malware after successful SSH/Telnet interaction.
- The same payload is delivered through Cowrie/Dionaea while related infrastructure probes SIP or ICS services.
- A source with clean reputation uses valid sector-native protocol grammar, making it higher priority than noisy known scanners.
- Credential themes map to sectors: PBX terms against VoIP, PACS/radiology terms against DICOM, PLC/vendor terms against ICS.
- JA3/HASSH/P0f fingerprints link otherwise rotating IPs into infrastructure clusters.
- Suricata CVE signatures can be tied to actual application-layer behavior and payload outcomes.

This supports finding types like:

- `sector_adaptive_campaign`
- `cross_sector_actor_cluster`
- `generic_to_sector_native_escalation`
- `payload_plus_protocol_campaign`
- `low_reputation_high_intent_actor`

## 4. What Not To Ingest

Do **not** ingest raw full transcripts by default, especially LLM-backed conversations. Store references/provenance and deterministic summaries. Raw text is high-volume, poisoning-prone, expensive to diff, and likely to pollute evidence with attacker-ASSERTED claims.

Do **not** duplicate tsec malware collection, sandboxing, feed generation, or enrichment. Consume immutable tsec outputs and link by hash/session/source.

Do **not** create findings for every Suricata alert, HTTP request, credential attempt, JA3, or p0f fingerprint. Those are observations, not findings.

Do **not** over-normalize every niche honeypot immediately. A shallow, stable schema for protocol operation and source/session linkage is better than brittle deep parsers.

Do **not** treat attacker-declared identity, goals, country, employer, or tool names as OBSERVED evidence.

## 5. What Breaks At Scale

The registry cannot remain “one interesting event equals one finding.” At these volumes it needs aggregation-first semantics.

Required changes:

- Add explicit **observation groups** beneath findings: credential cluster, protocol cluster, payload cluster, source cluster.
- Separate finding identity from daily evidence. Stable IDs should be based on deterministic campaign keys, not individual events.
- Add decay and saturation. The 900,000th identical credential attempt should update counts, not priority.
- Add per-source-family priority models. A DICOM C-ECHO from one clean IP may matter more than 50,000 generic SSH failures.
- Add confidence and intent dimensions separately from severity. Sector-native grammar should raise intent even without malware.
- Add poisoning-risk weighting per evidence field. Raw LLM/web text should carry lower evidentiary weight than parsed protocol operations or sandbox verdicts.
- Add rollup findings: source-level, ASN-level, payload-level, sector-level, and cross-sector campaign-level.
- Add retention tiers: raw references in source stores, compact normalized observations in analytics tables, durable findings in registry.

The priority model should reward **rarity, sector specificity, protocol validity, cross-source linkage, payload confirmation, novelty, and reputation-blindness**. It should penalize raw volume when the behavior is repetitive, generic, or already explained by known commodity scanning.
