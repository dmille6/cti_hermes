# cti_hermes

Central repository for the cti_hermes project and all data produced while
working on it — by humans, Claude, ChatGPT, or any other tool.

## Why this repo exists

Different AI assistants can't talk to each other directly. This repo is the
shared workspace: everything worth keeping (code, data, notes, decisions) gets
committed here, so any tool — or person — can pick up the current state by
cloning the repo.

## Layout

- `src/` — project source code
- `data/` — datasets and data files
- `notes/` — shared context, research, and decisions
- `notes/handoffs/` — per-session handoff notes between tools

## For AI assistants

Read [AGENTS.md](AGENTS.md) before doing anything. It contains the shared
instructions and the cross-tool handoff protocol.
