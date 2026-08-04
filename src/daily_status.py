#!/usr/bin/env python3
"""Daily status brief — the one thing the operator reads each morning.

Deliberately short. On a quiet day this should be four lines and nothing else:
sensors green, no new findings, N continuing. Everything detailed lives in the
per-analysis reports and the findings registry, linked by finding id.

It answers three questions in order:
  1. Is everything working?          (system health)
  2. What changed?                   (registry delta: new / escalated / resurfaced)
  3. What needs me?                  (unreviewed high-priority findings)

READ-ONLY. No LLM call — this is status, and status should never be
paraphrased by a model that might soften or invent it.

Usage: daily_status.py [--hours 24] [--write]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import findings  # noqa: E402
import llm  # noqa: E402

ES = "http://10.0.0.75:64298"
OUT_DIR = "/home/mike/reports"
SECTORS = {
    "db1lapetro": "petrochemical", "db4lamedtech": "medical technology",
    "rmm-prod-01": "remote management", "pbx-prod-01": "VoIP / telephony",
    "hivev2": "general hive",
}


def es(body):
    req = urllib.request.Request(f"{ES}/logstash-*/_search",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def health(hours):
    """Every check returns (ok, label, detail). Anything not ok surfaces."""
    checks = []

    # --- sensors reporting recently ---
    r = es({"size": 0, "query": {"range": {"@timestamp": {"gte": "now-2h"}}},
            "aggs": {"s": {"terms": {"field": "t-pot_hostname.keyword", "size": 20}}}})
    live = {b["key"]: b["doc_count"] for b in r["aggregations"]["s"]["buckets"]}
    missing = [h for h in SECTORS if h not in live]
    checks.append((not missing, "sensors",
                   f"{len(live)}/{len(SECTORS)} reporting in last 2h"
                   + (f" — SILENT: {', '.join(missing)}" if missing else "")))

    # --- ingest volume vs the trailing week ---
    cur = es({"size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
              "track_total_hits": True})["hits"]["total"]["value"]
    wk = es({"size": 0,
             "query": {"range": {"@timestamp": {"gte": "now-8d", "lte": f"now-{hours}h"}}},
             "track_total_hits": True})["hits"]["total"]["value"]
    daily_mean = wk / 7 if wk else 0
    drift = ((cur - daily_mean) / daily_mean * 100) if daily_mean else 0
    checks.append((abs(drift) < 60, "ingest",
                   f"{cur:,} events ({drift:+.0f}% vs 7-day mean)"))

    # --- how much traffic carries any reputation label ---
    rep = es({"size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
              "aggs": {"r": {"filter": {"exists": {"field": "ip_rep"}}}}})
    covered = rep["aggregations"]["r"]["doc_count"]
    pct = (covered / cur * 100) if cur else 0
    checks.append((True, "reputation coverage", f"{pct:.0f}% of events labelled"))

    # --- Galah's LLM backend, which fails silently into the type field ---
    g = es({"size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "aggs": {"e": {"filter": {"terms": {"type.keyword": [
                "invalidJSONResponse", "contentGenerationError"]}}},
                "ok": {"filter": {"term": {"type.keyword": "Galah"}}}}})
    ge, go = g["aggregations"]["e"]["doc_count"], g["aggregations"]["ok"]["doc_count"]
    grate = (ge / (ge + go) * 100) if (ge + go) else 0
    checks.append((grate < 5, "galah llm", f"{grate:.1f}% failure rate ({ge:,} errors)"))

    # --- did last night's analyses actually run? ---
    today = str(date.today())
    stale = [n for n, f in (("sector-diff", f"{OUT_DIR}/{today}-sector-diff.md"),
                            ("cowrie-ttp", f"{OUT_DIR}/{today}-cowrie-ttp.md"))
             if not os.path.exists(f)]
    checks.append((not stale, "analysis jobs",
                   "all ran today" if not stale else f"MISSING: {', '.join(stale)}"))

    # --- narrative model reachable ---
    cfg = llm.config()
    try:
        urllib.request.urlopen(f"{cfg['base_url'].rstrip('/')}/models", timeout=10)
        checks.append((True, "narrative model", f"{cfg['model']} reachable"))
    except Exception as e:
        checks.append((False, "narrative model", f"UNREACHABLE: {type(e).__name__}"))

    # --- disk ---
    du = shutil.disk_usage(OUT_DIR)
    free_pct = du.free / du.total * 100
    checks.append((free_pct > 10, "disk",
                   f"{du.free // 2**30} GB free ({free_pct:.0f}%)"))
    return checks


def render(checks, d, hours):
    bad = [c for c in checks if not c[0]]
    lines = [f"# Daily Status — {date.today()}",
             f"\n_Window: last {hours}h. Generated deterministically; no model in this path._",
             "\n## Systems"]
    if bad:
        lines.append(f"**{len(bad)} issue(s) need attention:**")
        for _, label, detail in bad:
            lines.append(f"- ⚠️  **{label}** — {detail}")
        lines.append("\nOther checks OK: "
                     + ", ".join(f"{l} ({dt})" for ok, l, dt in checks if ok))
    else:
        lines.append("All green.")
        for _, label, detail in checks:
            lines.append(f"- {label}: {detail}")

    lines.append("\n## What changed")
    changed = False
    for key, heading in (("new", "New"), ("escalated", "Escalated"),
                         ("resurfaced", "Resurfaced")):
        items = d.get(key) or []
        if not items:
            continue
        changed = True
        lines.append(f"\n**{heading} ({len(items)})**")
        for i in items[:8]:
            sect = ", ".join(i["sectors"]) or "unknown"
            lines.append(f"- `{i['id']}` [p{i['priority']}] {i['title'][:88]}"
                         f"  \n  _{sect} · day {i['days_seen']} · confidence {i['confidence']}_")
        if len(items) > 8:
            lines.append(f"- …and {len(items) - 8} more")
    if not changed:
        lines.append("Nothing new, escalated, or resurfaced.")

    nr = d.get("needs_review") or []
    lines.append("\n## Needs your decision")
    if nr:
        lines.append(f"{len(nr)} unreviewed finding(s) at priority ≥50:")
        for i in nr[:6]:
            lines.append(f"- `{i['id']}` [p{i['priority']}] {i['title'][:80]}")
        lines.append("\nTriage with: `findings.py set <id> "
                     "true_positive|benign|known` or `findings.py suppress <id>`")
    else:
        lines.append("Nothing awaiting review.")

    lines.append(f"\n---\n_{len(d.get('continuing') or [])} findings continuing · "
                 f"{len(d.get('quiet') or [])} gone quiet · "
                 f"{d.get('suppressed_count', 0)} suppressed_")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()

    checks = health(a.hours)
    c = findings.conn()
    d = findings.delta(c, a.hours)
    text = render(checks, d, a.hours)

    if a.write:
        out = f"{OUT_DIR}/{date.today()}-daily-status.md"
        with open(out, "w") as f:
            f.write(text)
        print(f"wrote {out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
