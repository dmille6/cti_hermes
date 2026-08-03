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

Existing services: T-Pot hive (ELK stack), OpenCTI server. External feeds:
AlienVault OTX, CrowdStrike Falcon, Google Threat Intelligence.

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

## Daily intel pipeline (target)

1. Scheduled automation queries T-Pot ES: last-24h attack aggregations
   (top sources, new CVEs/exploits, Cowrie credentials, malware hashes).
2. Extract novel IOCs; enrich via OTX / GTI / Falcon MCPs.
3. Cross-reference and write curated findings into OpenCTI (STIX) via xtm-mcp.
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

## Open questions

- Which box hosts the agent server (VM on one of the Linux hosts?).
- Elastic version on T-Pot → decides which ES MCP server to use.
- Report template/format for `notes/reports/`.
