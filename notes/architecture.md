# cti_hermes — Architecture Plan (2026-08-03)

## Mission

An autonomous CTI agent server that pulls data from the T-Pot hive honeynet
(Elasticsearch), OpenCTI, OTX, Google Threat Intelligence, and CrowdStrike to
produce intelligence reports and findings — all inference local via Ollama.

## Infrastructure

| Host | Hardware | Role |
|------|----------|------|
| Mac Studio | M4 Max, 128 GB RAM | Primary reasoning/report model (large model via Ollama) |
| Linux #1 | RTX 5080, 16 GB VRAM | Fast small-model tasks: IOC extraction, enrichment, embeddings |
| Linux #2 | RTX A6000, 48 GB VRAM | Workhorse mid/large model (pending setup) |
| Agent server | TBD (own box/VM) | Hermes Agent + MCP servers; talks to Ollama over OpenAI-compatible API |

Existing services: T-Pot hive (ELK stack), OpenCTI server, MISP instance.
External feeds: AlienVault OTX, CrowdStrike Falcon, Google Threat
Intelligence.

## Agent framework: Hermes Agent (NousResearch)

- MIT-licensed, self-improving agent: writes/refines its own Python/Bash
  "skills" (procedural memory), persistent cross-session memory.
- Any OpenAI-compatible backend → works with Ollama (`/v1` endpoint).
- Native MCP client → all integrations below plug in as MCP servers.
- Cron-style scheduled automations + messaging gateway (Telegram, Slack,
  Discord, Signal, email) for report delivery.
- Identity/goals defined in a SOUL.md-style file → give it a CTI analyst brief.

## Integration layer (MCP servers)

| Source | MCP server | Status |
|--------|-----------|--------|
| OpenCTI | Filigran official `xtm-mcp` (bundled with OpenCTI 6.8+) | official |
| T-Pot Elasticsearch | `elastic/mcp-server-elasticsearch` (deprecated but works; successor is Agent Builder MCP endpoint in Elastic 9.2+) or `cr7258/elasticsearch-mcp-server` | official / community |
| CrowdStrike | `CrowdStrike/falcon-mcp` (public preview) | official |
| Google TI | `google/mcp-security` (GTI + SecOps + SCC servers) | official |
| OTX + AbuseIPDB + GreyNoise + abuse.ch | `aplaceforallmystuff/mcp-threatintel` or `4R9UN/fastmcp-threatintel` (STIX output) | community |

## Model assignments (initial)

- **Mac Studio (128 GB)**: Hermes 4 70B q4 (~40 GB) — the model the agent
  framework is tuned for — or gpt-oss-120b. Report drafting, deep reasoning.
- **A6000 (48 GB)**: Hermes 4 70B q4 or Qwen3-32B. Enrichment/tool-calling
  workhorse once online.
- **RTX 5080 (16 GB)**: Qwen3-14B / Foundation-Sec-8B (Cisco security-tuned)
  for triage, IOC extraction, embeddings.
- Optional: LiteLLM proxy on the agent server as a single OpenAI-compatible
  gateway routing to all three Ollama hosts.

## Enrichment layer: IntelOwl + MISP (decided 2026-08-03)

- **IntelOwl** is the enrichment engine. Deterministic code (not the LLM)
  submits observables; IntelOwl fans out to analyzers (OTX, AbuseIPDB,
  GreyNoise, VirusTotal/GTI, Shodan, MISP lookup, etc.) and aggregates
  results.
- **IntelOwl connectors** push enrichment results to both MISP and OpenCTI
  automatically — no custom glue for the write path.
- **MISP (already running)** provides:
  - Warninglists + taxonomies for known-benign filtering *before* enrichment
    (don't burn API quota enriching Googlebot or cloud-provider ranges).
  - A second lookup source: "have my own sensors seen this before?"
  - The community-sharing path (MISP events → sharing groups) alongside OTX.
- **MISP ↔ OpenCTI sync** via the official OpenCTI MISP connector, one
  direction at a time (recommend MISP → OpenCTI to start) to avoid feedback
  loops. PyMISP for any custom scripting.
- Enrichment order per IOC: MISP warninglist check → MISP/OpenCTI dedup
  lookup → IntelOwl analyzer fan-out → scored result into OpenCTI (STIX) and
  MISP event.

## Daily intel pipeline (target)

1. Scheduled automation queries T-Pot ES: last-24h attack aggregations
   (top sources, new CVEs/exploits, Cowrie credentials, malware hashes).
2. Extract novel IOCs (deterministic extractors); filter against MISP
   warninglists; enrich via IntelOwl analyzer fan-out (OTX, GTI, Falcon,
   AbuseIPDB, GreyNoise, MISP lookup).
3. IntelOwl connectors write scored results to MISP and OpenCTI; curated
   findings land in OpenCTI as STIX. (MCP servers remain the *interactive*
   query layer for the analyst agent.)
4. Draft Markdown intel report → commit to this repo (`notes/reports/`).
5. Deliver summary via messaging gateway.

## Security guardrails (non-negotiable)

- **Honeypot data is attacker-controlled input.** Everything from T-Pot
  (usernames, URLs, payloads) may contain prompt-injection attempts. The agent
  must treat it as data, never instructions; keep the ingest path read-only.
- Read-only API keys for ES, OTX, GTI, CrowdStrike. OpenCTI write access via a
  dedicated low-privilege connector account; human review before anything is
  shared outward to OTX/other platforms.
- Agent server on an isolated VLAN; no credentials for anything it doesn't need.

## Peer review amendments (2026-08-03, via Codex CLI / ChatGPT)

Full review: `notes/reviews/2026-08-03-chatgpt-codex.md`. Accepted changes:

1. **Deterministic core, LLM as analyst.** The pipeline (collection, IOC
   extraction, dedup, STIX serialization, publication gates) is owned by
   deterministic code; LLMs summarize, classify, cluster, and draft — they do
   not orchestrate writes. Hermes Agent remains the interactive analyst and
   report drafter, not the workflow authority.
2. **Role separation**: no-tools extraction worker → read-only enrichment
   worker → STIX writer that accepts only schema-validated bundles.
   Memory/skill-authoring disabled for any session touching raw honeypot data.
3. **Add to stack**: IntelOwl (enrichment fan-out), MISP warninglists + CIRCL
   hashlookup (known-benign filtering), `cti-python-stix2`/`attackcti`
   (proper STIX/ATT&CK handling), pySigma + YARA for detection outputs.
4. **Prefer official OpenCTI connectors** over MCP wrappers where they exist;
   restrict falcon-mcp to the `intel` module only.
5. **STIX discipline**: observed-data + sightings by default; promote to
   `indicator` only with analytic confidence; deterministic external IDs to
   prevent duplicates; `valid_until` on everything.
6. **Report products**: daily tactical brief + weekly analytic report with
   ATT&CK heatmap (templates in the review doc).
7. **Ops hardening (later phases)**: queue/checkpoint layer (Prefect or
   Temporal) instead of bare cron; benchmark vLLM vs Ollama on the NVIDIA
   hosts for concurrent enrichment throughput; adversarial prompt-injection
   test corpus built from real T-Pot payloads.

## Open questions

- Which box hosts the agent server (VM on one of the Linux hosts?).
- Elastic version on T-Pot → decides which ES MCP server to use.
- Report template/format for `notes/reports/`.
