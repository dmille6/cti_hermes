# cti_hermes Architecture Peer Review

Reviewed: `notes/chatgpt-review-request.md`, `notes/architecture.md`, and latest handoff note.

## 1. Weaknesses And Failure Modes

The largest design risk is that the agent framework is doing too much: scheduling, tool selection, enrichment logic, report generation, memory, and delivery. For CTI production workflows, keep the LLM as an analyst-assistant component, not the workflow authority. Use deterministic code for extraction, normalization, deduplication, STIX object creation, confidence scoring, and publication gates.

Specific risks:

- **MCP tool blast radius**: MCP servers expose broad tool surfaces. CrowdStrike’s own MCP docs recommend module restriction and dynamic mode because loading all modules inflates context and capability surface. Use allowlisted modules only, for example `intel`, not detections/hosts unless needed.
- **Elasticsearch MCP uncertainty**: `elastic/mcp-server-elasticsearch` is deprecated and superseded by Elastic Agent Builder MCP in Elastic 9.2+. If T-Pot’s Elastic version cannot support the newer endpoint, prefer a small custom read-only query service over a broad general ES MCP.
- **OpenCTI data pollution**: Automated STIX writes can create duplicate indicators, weak relationships, bad confidence scores, and noisy reports. Require deterministic upsert keys, source markings, confidence thresholds, decay/expiration, and review queues.
- **Local model tool-calling reliability**: Ollama’s OpenAI compatibility is partial. Tool calls, JSON mode, and reasoning controls exist, but behavior varies by model. Treat LLM output as untrusted until schema-validated.
- **Honeypot bias**: T-Pot sees opportunistic internet noise. Without baseline comparison, ASN/geography normalization, scanner identification, and known-benign filtering, reports may overstate commodity scans as meaningful campaigns.
- **No explicit eval loop**: The plan lacks regression tests for IOC extraction, ATT&CK tagging, STIX mapping, and prompt-injection resistance. Build a gold corpus from real T-Pot events plus adversarial payloads.
- **Credential leakage through memory**: Hermes persistent memory and self-authored skills are useful but risky. Disable memory/skill writes for raw-ingest sessions, or run separate profiles with no long-term memory for untrusted data handling.
- **No queue/checkpoint layer**: A daily cron pipeline is fragile. If GTI/OTX/Falcon rate-limit or OpenCTI rejects a bundle, you need retries, idempotency, dead-letter queues, and replay.
- **Community MCP supply-chain risk**: Community threat-intel MCPs may be fine prototypes, but they should not handle privileged credentials until pinned, reviewed, containerized, and network-restricted.

## 2. Missing Open-Source Projects, Tools, Models

Consider adding these:

- **MISP / PyMISP**: Still a core open-source CTI sharing platform. Even if OpenCTI is primary, MISP taxonomies, galaxies, warninglists, and sharing communities are valuable.
- **IntelOwl**: Strong fit for enrichment orchestration across IP/domain/URL/hash/file analyzers. It can reduce custom enrichment glue and keep LLMs out of API fan-out logic.
- **OpenCTI native connectors**: Prefer official OpenCTI connectors where available before adding MCP wrappers. OpenCTI connectors already handle STIX 2.1 ingestion/enrichment patterns.
- **TAXII/STIX libraries**: `cti-python-stix2`, `taxii2-client`, and `attackcti` for structured ATT&CK/STIX handling.
- **SigmaHQ + pySigma**: Generate detection logic from recurring honeypot behaviors.
- **YARA / YARA-X, capa, FLOSS, ClamAV**: For malware samples or payload artifacts.
- **Zeek, Suricata, Arkime**: If packet/full-flow visibility exists or can be added around sensors.
- **Timesketch or OpenSearch Dashboards saved objects**: For analyst timelines and investigations.
- **CIRCL tools**: `hashlookup`, CVE Search, MISP warninglists, and known-good filters.
- **SpiderFoot, IVRE, Amass**: Useful for passive context and scanner/infrastructure profiling.
- **RAG/embedding stack**: `bge-m3`, `nomic-embed-text`, `mxbai-embed-large`, or Jina embeddings; add `bge-reranker-v2-m3` for report-source retrieval.
- **NER/extraction models**: GLiNER, NuExtract, or constrained regex/parser pipelines before general LLM extraction.
- **Security guard models**: Llama Guard-class classifiers can help flag unsafe prompt content, but should supplement, not replace, hard isolation.

## 3. Intel Report Structure

Use separate daily tactical and weekly analytic products.

Daily report:

```markdown
# Daily Honeynet Intelligence Brief — YYYY-MM-DD

## Executive Summary
3-5 bullets: what changed, what matters, confidence.

## Key Changes
- New source infrastructure
- New malware hashes
- New CVEs/exploit paths
- New credentials/commands/payloads
- Significant volume anomalies

## High-Confidence Indicators
Table: indicator, type, first_seen, last_seen, count, source_sensor, enrichment hits, confidence, TLP, expiration.

## Activity Clusters
For each cluster: behavior, evidence, affected honeypot services, related indicators, ATT&CK techniques, confidence, analyst notes.

## TTPs Observed
ATT&CK tactic/technique/sub-technique, evidence, mapping rationale, confidence.

## Enrichment Summary
OTX/GTI/Falcon results, conflicts, provider confidence, links/reference IDs.

## Recommended Actions
Detection ideas, blocklist candidates, hunting queries, YARA/Sigma/Suricata ideas.

## Appendix
Raw evidence references, query IDs, STIX object IDs, rejected/low-confidence items.
```

Weekly report:

- Trends vs prior weeks.
- Repeated infrastructure and campaign-like clustering.
- Notable payload evolution.
- Top exploited services and CVEs.
- ATT&CK heatmap.
- Collection gaps and sensor health.
- “What changed enough to care?” section.

STIX mapping recommendations:

- IP/domain/URL/hash as `observed-data` plus SCOs.
- Promote to `indicator` only when there is analytic confidence and a useful pattern.
- Use `sighting` for sensor observations.
- Use `malware`, `tool`, `intrusion-set`, or `campaign` sparingly; do not infer actors from commodity IOCs alone.
- Add `relationship` objects with explicit rationale.
- Include `confidence`, `created_by_ref`, `object_marking_refs`, `external_references`, `valid_from`, and `valid_until`.
- Use deterministic external IDs to avoid duplicate OpenCTI objects.

ATT&CK tagging:

- Tag only behavior, not reputation. “SSH brute force” can map to Credential Access techniques if evidence supports it; an IP reputation hit alone should not.
- Store mapping rationale and confidence.
- Use `attackcti` or MITRE’s STIX/TAXII content rather than LLM free-form technique names.

## 4. Better Multi-Ollama Orchestration Patterns

LiteLLM is a good gateway choice, but do not confuse routing with orchestration. It can normalize OpenAI-compatible calls, apply retries/fallbacks, and route across deployments. It will not make one large inference run across multiple Ollama hosts.

Recommended pattern:

- **LiteLLM Proxy** as the single model endpoint.
- **Named model classes**: `extractor-small`, `enricher-mid`, `report-large`, `embedder`.
- **Task queue**: Celery/RQ/Arq for simple Python, or Temporal/Prefect/Dagster for durable workflows.
- **Per-task routing**: extraction to RTX 5080, enrichment to A6000, synthesis to Mac Studio.
- **Health checks and backpressure**: Prometheus/Grafana, queue depth, model latency, tokens/sec, GPU memory.
- **Schema-first calls**: all model responses validated with Pydantic/JSON Schema.
- **Fallbacks**: if report-large is down, degrade to weekly backlog rather than writing weak intel.

For NVIDIA hosts, benchmark **vLLM** or **llama.cpp server** against Ollama for throughput. Ollama is convenient; vLLM may be better for concurrent enrichment if the chosen models are supported.

## 5. Prompt-Injection Guardrails

Treat prompt injection as a data pipeline problem, not a prompt wording problem.

Actionable changes:

- **Never put raw honeypot text directly into an agent with write tools.** First parse it with deterministic extractors into typed fields.
- **Use taint tracking**: every field from T-Pot is `untrusted`. Untrusted fields may be summarized or classified, but never interpreted as instructions.
- **Separate roles**: one no-tools extraction worker, one enrichment worker with read-only external APIs, one OpenCTI writer that accepts only validated STIX bundles.
- **Disable memory and skill authoring for untrusted-ingest sessions.**
- **Escape and delimit evidence** in prompts, but do not rely on delimiters alone.
- **Constrain outputs** with JSON Schema/Pydantic and reject extra fields.
- **Use allowlisted tools per workflow step**, not global MCP access.
- **Containerize MCP servers** with egress restrictions. For example, the ES MCP should only reach T-Pot ES, not the internet.
- **Add adversarial tests**: usernames, URLs, shell commands, malware banners, and HTTP payloads that say “ignore previous instructions”, request secrets, or attempt tool use.
- **Human approval before external sharing** should include a diff of STIX objects and a rendered report, not just the final prose.

Best design change: make the LLM generate recommendations and summaries from already-normalized evidence, while deterministic code owns collection, enrichment joins, STIX serialization, deduplication, and publication.

## Sources Consulted

- Hermes Agent MCP/security docs: https://hermes-agent.nousresearch.com/docs/
- OpenCTI connectors/integrations docs: https://docs.opencti.io/latest/
- Elastic MCP server deprecation and Agent Builder MCP docs: https://github.com/elastic/mcp-server-elasticsearch and https://www.elastic.co/docs/solutions/search/agent-builder/mcp-server
- Google MCP Security docs: https://github.com/google/mcp-security
- CrowdStrike Falcon MCP docs: https://developer.crowdstrike.com/falcon-mcp/
- Ollama OpenAI compatibility: https://docs.ollama.com/api/openai-compatibility
- LiteLLM proxy docs: https://docs.litellm.ai/
- MISP: https://www.misp-project.org/
- IntelOwl: https://github.com/intelowlproject/IntelOwl
- ATT&CK CTI Python client: https://pypi.org/project/attackcti/
