# AGENTS.md — Shared AI Assistant Instructions

This file is the **single source of truth** for all AI assistants working in this
repository (Claude, ChatGPT/Codex, Copilot, Gemini, etc.). If you are an AI
assistant reading this: these instructions apply to you.

## Project

**cti_hermes** — central repository for the project and all data produced by AI
assistants, so that multiple tools can collaborate on the same work.

## Repository layout

| Path | Purpose |
|------|---------|
| `src/` | Project source code |
| `data/` | Datasets and data files saved by any assistant or human |
| `notes/` | Shared context: decisions, research, working notes |
| `notes/handoffs/` | Cross-tool handoff log (see below) |

## Cross-tool handoff protocol

Because multiple AI tools work in this repo, each session that makes meaningful
changes should leave a short handoff note so the next tool (or human) can pick
up where it left off.

1. Create or append to `notes/handoffs/YYYY-MM-DD-<tool>.md`
   (e.g. `2026-08-03-claude.md`, `2026-08-03-chatgpt.md`).
2. Record: what was done, what's in progress, open questions, and anything
   surprising you learned.
3. **Read the most recent handoff notes before starting work.**

## Conventions

- Commit messages: short imperative subject line; mention which tool authored
  the change if it was AI-generated.
- Data files go in `data/`, never scattered in the repo root.
- Don't commit secrets, API keys, or credentials. Ever.
- Prefer plain, portable formats (Markdown, JSON, CSV) so every tool can read
  what another wrote.
- If you change these instructions, note it in your handoff.
