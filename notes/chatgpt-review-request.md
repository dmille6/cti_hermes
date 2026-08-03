# Peer-review request: cti_hermes architecture

*Prompt prepared by Claude for ChatGPT (or any other AI reviewer). Paste
everything below into the other tool; save its response to
`notes/reviews/YYYY-MM-DD-chatgpt.md`.*

---

I'm building an autonomous cyber threat intelligence (CTI) system called
cti_hermes and want your critical review of the architecture below, plus any
additional ideas, tools, or risks I've missed. This is a defensive security
project: I run a T-Pot hive honeynet and share threat intel with the community.

## My infrastructure

- T-Pot hive honeynet (multiple sensors) with its Elasticsearch/ELK stack
- OpenCTI server
- Threat intel platform accounts: AlienVault OTX, CrowdStrike Falcon, Google
  Threat Intelligence (GTI)
- Three Ollama LLM servers: Mac Studio M4 Max 128 GB RAM; Linux with RTX 5080
  16 GB VRAM; Linux with RTX A6000 48 GB VRAM (coming online soon)

## Planned architecture

- **Agent framework**: NousResearch's Hermes Agent (MIT) on a dedicated agent
  server. Chosen for: OpenAI-compatible API support (works with Ollama),
  native MCP client, self-authored reusable "skills" (procedural memory),
  cron-style scheduled automations, messaging gateway for report delivery.
- **Integration layer — MCP servers**: Filigran's official xtm-mcp for OpenCTI
  (bundled with OpenCTI 6.8+); elastic/mcp-server-elasticsearch (or
  cr7258/elasticsearch-mcp-server) for the T-Pot ELK stack;
  CrowdStrike/falcon-mcp (official, public preview); google/mcp-security for
  GTI; community mcp-threatintel for OTX/AbuseIPDB/GreyNoise/abuse.ch.
- **Model placement**: Hermes 4 70B q4 or gpt-oss-120b on the Mac Studio
  (report drafting, deep reasoning); Hermes 4 70B q4 / Qwen3-32B on the A6000
  (enrichment workhorse); Qwen3-14B or Foundation-Sec-8B on the 5080 (IOC
  extraction, triage, embeddings). Possibly LiteLLM as a single gateway
  routing across the three Ollama hosts.
- **Daily pipeline**: scheduled query of T-Pot ES for last-24h attack
  aggregations → extract novel IOCs → enrich via OTX/GTI/Falcon → write
  curated STIX findings into OpenCTI → draft Markdown intel report committed
  to a shared GitHub repo → deliver summary via messaging.
- **Guardrails**: honeypot data treated as attacker-controlled input (prompt
  injection risk); read-only API keys on ingest paths; low-privilege OpenCTI
  write account; human review before sharing anything outward; agent server
  on an isolated VLAN.

## Questions for you

1. What weaknesses or failure modes do you see in this design?
2. Are there open-source projects, MCP servers, or models I should consider
   that aren't listed?
3. How would you structure the intel reports (daily/weekly formats, STIX
   mapping, MITRE ATT&CK tagging) for maximum value?
4. Any better patterns for orchestrating multiple Ollama hosts?
5. What would you do differently about the prompt-injection guardrails,
   given the agent ingests raw honeypot data?
