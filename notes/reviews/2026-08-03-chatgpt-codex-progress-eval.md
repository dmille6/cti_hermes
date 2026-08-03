# CTI Hermes Progress Review — 2026-08-03

## 1. Progress Check

Claude made real progress today: repo initialized, architecture captured, peer review amendments folded in, VM provisioned, Hermes Agent installed, Ollama backend working, and both T-Pot Elasticsearch and OpenCTI MCPs wired successfully.

The sequencing is mostly understandable for a fast prototype, but it diverged from the agreed build order.

Agreed order after Session 4 was:

1. Deploy IntelOwl.
2. Enable MISP → OpenCTI connector.
3. Install Hermes Agent and MCP wiring.

Actual order became:

1. VM provisioned.
2. Hermes Agent installed.
3. T-Pot ES MCP wired.
4. OpenCTI MCP wired.
5. IntelOwl and MISP connector deferred.

That is acceptable for proving the interactive analyst loop, but it skips the deterministic enrichment core that the earlier review explicitly recommended. The risk is that the project now has a powerful agent with broad live data access before the safer pipeline components exist.

The biggest skipped items that may bite later:

- No low-privilege OpenCTI service account yet.
- No ES read-only/auth boundary yet.
- No deterministic extraction/enrichment/STIX path yet.
- No prompt-injection test corpus yet.
- No isolation between raw honeypot analysis and agent memory/tool use.
- No durable fix for `OLLAMA_CONTEXT_LENGTH=65536`.

The current state is a good lab milestone, not yet a safe production workflow.

## 2. Implementation Audit

### Hermes Agent On Ubuntu VM

Hermes Agent v0.20 on `ctihermes` is a reasonable analyst-layer choice. The VM sizing, 8 vCPU / 16 GB RAM / 195 GB disk, is fine for orchestration, MCP servers, Docker services, cron jobs, and report generation. It is not sized for local model inference, but that is not the plan.

Concern: Hermes has persistent memory and skill-writing behavior. That is useful for interactive work, but dangerous when raw T-Pot data is in context. Honeypot payloads are attacker-controlled. The SOUL.md warning helps, but prompt text is not a hard control.

Recommendation: create separate Hermes profiles or operating modes:

- `analyst-interactive`: MCP read tools allowed, memory allowed cautiously.
- `raw-ingest`: no memory, no skill authoring, no write tools.
- `publisher`: no raw honeypot text, accepts only validated structured artifacts.

### Ollama On Mac Studio

Pointing Hermes at the Mac Studio Ollama endpoint is pragmatic. Hermes-4.3-36B Q6_K with 64K context is a plausible first model for local CTI analysis and report drafting.

Issues:

- `OLLAMA_CONTEXT_LENGTH` set via `launchctl setenv` is not reboot-persistent.
- No model gateway yet, so routing/fallbacks are manual.
- Tool-call reliability should be tested with fixtures, not assumed from one successful smoke test.

Fix soon:

- Make the Ollama env persistent via LaunchAgent or the supported Ollama app mechanism.
- Add a health check that verifies model name, context length, and tool-call behavior before scheduled jobs run.
- Later put LiteLLM in front if multiple model hosts become active.

### T-Pot Elasticsearch MCP

The official Elastic MCP working against ES 9.3.5 is useful, and the end-to-end aggregation test is a strong proof point.

But this is currently the highest-risk component:

- T-Pot ES has no auth on the LAN.
- The agent has full query DSL access.
- Raw attacker-controlled documents can be passed into an autonomous agent.
- The MCP can likely issue expensive or broad queries.
- LAN-only is not a sufficient control if the agent host is compromised.

This should be treated as a temporary prototype path. The safer long-term design is a narrow read-only query service with allowlisted aggregations and capped result sizes.

Minimum near-term hardening:

- Put auth or a reverse proxy in front of ES.
- Restrict access to only `ctihermes`.
- Use an ES user/API key with read-only privileges if supported in the T-Pot setup.
- Limit indices to required patterns.
- Add query size/time limits.
- Avoid returning raw payload fields unless explicitly requested.

### OpenCTI MCP

Using archived FiligranHQ `xtm-mcp` in a venv is acceptable as a temporary bridge, especially because OpenCTI 6.9.16 does not appear to have the desired embedded MCP path in use yet.

Main concern: the token in `~/.hermes/config.yaml` is the operator’s main API key. That is too much authority for an MCP exposed to an agent.

Fix this before any scheduled automation or write path:

- Create a dedicated OpenCTI service account.
- Start read-only if the MCP is only for analyst lookup.
- Use a separate low-privilege connector/writer account later for curated STIX writes.
- Rotate the current token after replacing it, because it has already been placed in an agent config context.

### SOUL.md Guardrails

The CTI analyst identity and “honeypot data is untrusted” instruction are good, but they are advisory controls. They should not be counted as security boundaries.

The planned T-Pot sensor glossary is useful and should be added. The Suricata/P0f mislabeling shows the model needs local ontology/context. That said, glossary work is less urgent than credentials and blast-radius reduction.

## 3. Security Gaps To Fix First

Priority order:

1. Replace the OpenCTI main API token  
   Create a dedicated low-privilege account/token for Hermes. Use read-only for MCP lookup. Do not let the agent hold the operator’s main key.

2. Put a boundary in front of T-Pot ES  
   No-auth LAN Elasticsearch plus full MCP query DSL is the biggest blast-radius issue. Add auth, source-IP restriction, reverse proxy, or a narrow query facade. Cap query size and block raw payload retrieval by default.

3. Disable or isolate memory/skill-writing for raw honeypot sessions  
   Prompt injection from honeypot data is not theoretical. Raw T-Pot fields should never enter a session that can persist memory, author skills, or use write-capable tools.

4. Split read and write paths  
   MCP should remain interactive/read-oriented. OpenCTI/MISP writes should come from deterministic code that validates STIX bundles and uses a dedicated writer identity.

5. Build a prompt-injection regression corpus  
   Use real T-Pot examples: usernames, HTTP paths, payloads, banners, shell commands, URLs. Include attempts to leak config, alter instructions, invoke tools, or write false intel.

6. Make model/runtime config durable  
   Persist `OLLAMA_CONTEXT_LENGTH=65536`, and add a preflight check before cron jobs.

## 4. Next Steps Review

Current proposed next steps:

1. SOUL glossary.
2. Daily cron brief with repo deploy key.
3. IntelOwl + MISP.

I would reorder.

Recommended next order:

1. Create low-privilege OpenCTI token and rotate out the main token.
2. Add an ES access boundary: auth/proxy/query facade/source restriction.
3. Make Ollama 64K context persistent and add a simple health check.
4. Add SOUL glossary for T-Pot sensors.
5. Build a read-only daily brief prototype that writes locally first, without repo deploy key.
6. Add repo deploy key only after the brief cannot leak secrets or raw attacker text into committed reports.
7. Deploy IntelOwl and wire MISP/OpenCTI connectors.
8. Add MISP warninglist prefiltering before enrichment.
9. Move from Hermes cron to a deterministic scheduled script or lightweight workflow runner once writes/enrichment begin.

I would not put the repo deploy key on the VM until the credential and prompt-injection issues are tightened. A daily report job that can query raw honeypot data, use MCP tools, and commit to the repo is exactly the kind of path where prompt injection can become durable contamination.

## Bottom Line

Today’s work successfully proved that Hermes can act as an interactive CTI analyst over live T-Pot and OpenCTI data. That is a meaningful milestone.

But the implementation is now ahead of the safety architecture. Before adding scheduled reports, deploy keys, IntelOwl writes, or MISP/OpenCTI publication flows, reduce the blast radius: replace the OpenCTI token, constrain ES access, isolate raw honeypot sessions, and keep deterministic code in charge of enrichment and writes.
