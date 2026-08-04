# Narrative model: Hermes-4.3-36B vs qwen2.5:32b (2026-08-04)

Head-to-head on the real reporting task: identical prompt (the Cowrie TTP
evidence JSON), same endpoint, same settings.

| | hermes-cti-64k | qwen2.5:32b |
|---|---|---|
| Latency | 131.3 s | **89.9 s** |
| Completion tokens | 835 | 545 |
| ATT&CK ids correct | yes | yes |
| Off-menu / fabricated ids | none | none |
| Declined to map when nothing fit | no | **yes** |
| Identifier fidelity | **corrupted** a cluster fingerprint (`f51f8f9bd` for `f51f8c5f99bd`) | exact |
| Resident on the Studio | no — 98.7 GB, evicts the analytics tier | **yes — already pinned** |
| Analytical depth | richer: 3-4 techniques per cluster | thinner: 1-2 per cluster |

## Verdict

**Hermes-4.3-36B is more thorough. qwen2.5:32b is faster, more disciplined,
and free.**

The Hermes model produced a genuinely better read of the persistence cluster
(chmod/chattr + SSH authorized_keys → T1222 + T1098.004). But it also
mangled a cluster fingerprint mid-sentence — the same identifier-corruption
failure mode that already forced every table and every ATT&CK id in this
project to be generated deterministically. qwen2.5:32b instead said "no
direct MITRE ATT&CK technique fits this simple probe", which is exactly the
behaviour the prompt asks for and Hermes did not exhibit.

Given the architecture deliberately gives the model no arithmetic and no
identifier recall, **discipline is worth more here than depth**.

## The bigger realisation

The largest prompt this pipeline produces is **~12K tokens**
(sector-diff; the others are ~5K). Hermes Agent's **64K minimum context is a
framework requirement, not ours** — and it is the sole reason the Studio
memory problem exists:

- 64K context → Ollama allocates a 4× KV cache (default `NUM_PARALLEL=4`)
  → 98.7 GB → cannot coexist with the 88.7 GB the tsec pipeline pins.

The scheduled reports do not need an agent at all. They make **one
completion call** with a large prompt. They use no tools, no memory, no
skills — the `rawingest` profile explicitly disables all of it.

## Recommended split

| Workload | Engine | Why |
|---|---|---|
| Scheduled daily reports | **qwen2.5:32b via direct HTTP** to `:11436` | already resident → zero contention, zero eviction, no 64K floor, ~90 s |
| Interactive analyst work | **Hermes Agent** + Hermes-4.3-36B | MCP tools, exploration, memory — where an agent genuinely earns its place |

This removes the Hermes Agent dependency from the automated path entirely,
which also means a scheduled run cannot be broken by agent config drift, the
64K check, or model thrashing.

Cost: slightly thinner analysis per report. Mitigation: the deterministic
layer already carries the facts; the model only narrates them.
