#!/usr/bin/env python3
"""Findings registry — persistent state for cti_hermes.

Turns stateless daily snapshots into tracked findings with continuity, so the
system can say "this campaign began 2026-08-03, is still active, and expanded
from 24 to 31 hosts" instead of re-describing the same thing every morning.

Two design commitments worth understanding before changing anything:

1. PROVENANCE. Every piece of evidence is either OBSERVED (we saw the packets:
   a session happened, a command was typed at our sensor, an IP connected) or
   ASSERTED (attacker-controlled text claimed it: a URL inside a command, a
   hostname in a script, a filename, an actor name in a comment). Asserted
   evidence is trivially forged — an attacker can name any third party as
   their C2 and get us to publish it. Only OBSERVED evidence may support high
   confidence or external release.

2. FORGERY COST. Confidence is weighted by how expensive the behaviour would
   be to fake. A string in a command is free. Sustained multi-day activity
   from many hosts across sectors is not. See FORGERY_COST.

Usage:
  findings.py init                  create/upgrade the database
  findings.py list [--status s]     show current findings
  findings.py show <id>             full detail with evidence
  findings.py set <id> <disposition> [--note "..."]
  findings.py suppress <id> [--days N] [--note "..."]
  findings.py delta [--hours 24]    what changed (drives the daily brief)
"""
import argparse
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

DB = os.environ.get("CTI_FINDINGS_DB", "/home/mike/reports/findings.sqlite")

# How costly each finding type is for an adversary to fabricate. Drives the
# confidence ceiling: cheap-to-fake findings cannot reach high confidence on
# their own no matter how striking they look.
FORGERY_COST = {
    "asn_campaign": "high",          # needs many hosts, sustained, one provider
    "command_cluster": "medium",     # needs repeated real sessions
    "reputation_blind_actor": "medium",
    "credential_pattern": "low",     # trivially sprayed
    "asserted_infrastructure": "trivial",  # a URL typed into our shell
}

CONFIDENCE_CEILING = {"high": 90, "medium": 70, "low": 45, "trivial": 20}

STATUSES = ("new", "active", "escalated", "quiet", "resurfaced", "closed")
DISPOSITIONS = ("unreviewed", "true_positive", "benign", "known", "suppressed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  finding_id     TEXT PRIMARY KEY,
  finding_type   TEXT NOT NULL,
  title          TEXT NOT NULL,
  first_seen     TEXT NOT NULL,
  last_seen      TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'new',
  priority       INTEGER NOT NULL DEFAULT 0,
  confidence     INTEGER NOT NULL DEFAULT 0,
  forgery_cost   TEXT NOT NULL DEFAULT 'medium',
  disposition    TEXT NOT NULL DEFAULT 'unreviewed',
  suppressed_until TEXT,
  days_seen      INTEGER NOT NULL DEFAULT 1,
  scale          INTEGER NOT NULL DEFAULT 0,   -- hosts/sessions; drives 'escalated'
  sectors        TEXT NOT NULL DEFAULT '[]',
  evidence       TEXT NOT NULL DEFAULT '{}',   -- OBSERVED facts only
  asserted       TEXT NOT NULL DEFAULT '{}',   -- attacker-claimed, never published as fact
  notes          TEXT NOT NULL DEFAULT '',
  external_ok    INTEGER NOT NULL DEFAULT 0,
  -- Poisoning posture. Attacker-controlled content can describe what was
  -- typed; it can never establish who they are, what sector they targeted,
  -- or how important a finding is.
  poisoning_risk TEXT NOT NULL DEFAULT 'medium',   -- low|medium|high|critical
  poisoning_flags TEXT NOT NULL DEFAULT '[]',
  evidence_strength TEXT NOT NULL DEFAULT 'single', -- single|repeated|cross_source|cross_sensor|cross_sector
  corroboration  TEXT NOT NULL DEFAULT 'none',      -- none|internal_repeat|internal_cross_sensor|external
  reviewed_by    TEXT,
  reviewed_at    TEXT
);
CREATE TABLE IF NOT EXISTS history (
  finding_id TEXT NOT NULL,
  ts         TEXT NOT NULL,
  status     TEXT,
  priority   INTEGER,
  scale      INTEGER,
  event      TEXT
);
CREATE INDEX IF NOT EXISTS idx_hist ON history(finding_id, ts);
CREATE INDEX IF NOT EXISTS idx_status ON findings(status, priority);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def conn():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def make_id(finding_type, key):
    """Stable across runs: same underlying thing -> same id, always."""
    h = hashlib.sha256(f"{finding_type}|{key}".encode()).hexdigest()[:12]
    return f"{finding_type[:4]}-{h}"


def assess_poisoning(finding_type, scale, days_seen, unique_sources,
                     sectors, has_asserted):
    """How easily could an adversary have manufactured this? Returns
    (risk, flags, evidence_strength). Cheap-to-fake findings are capped."""
    flags = []
    if days_seen <= 1:
        flags.append("single_day_only")
    if unique_sources <= 1:
        flags.append("single_source_only")
    if has_asserted:
        flags.append("attacker_controlled_strings_present")
    if finding_type == "reputation_blind_actor" and unique_sources <= 1 and days_seen <= 1:
        # "Unknown to feeds" is absence of classification, not evidence of
        # importance — and an adversary can enter this queue deliberately by
        # using clean infrastructure.
        flags.append("reputation_blind_uncorroborated")

    if len(sectors) >= 2 and days_seen >= 3:
        strength = "cross_sector"
    elif unique_sources >= 3 and days_seen >= 3:
        strength = "cross_source"
    elif days_seen >= 2:
        strength = "repeated"
    else:
        strength = "single"

    if strength == "single" and len(flags) >= 2:
        risk = "high"
    elif strength == "single":
        risk = "medium"
    elif strength in ("repeated",):
        risk = "medium"
    else:
        risk = "low"
    return risk, flags, strength


def score(finding_type, sectors, scale, days_seen, rep_blind, has_malware,
          novel, sector_exclusive, poisoning_risk="medium"):
    """Deterministic priority. Inspectable on purpose — no ML, no LLM.

    Persistence is weighted heavily: a thing that is still here after several
    days is both more real and harder to have faked.
    """
    p = 0
    if sector_exclusive:
        p += 15          # targeting, not sweeping
    if rep_blind:
        p += 20          # nobody else can see this — our unique contribution
    if novel:
        p += 10
    if has_malware:
        p += 20
    p += min(scale, 30)              # hosts/sessions, capped
    p += min(days_seen * 5, 25)      # persistence
    if len(sectors) >= 3:
        p += 10          # cross-sector expansion is notable
    # An easily-manufactured finding cannot be top priority no matter how
    # striking it looks on one day's data.
    if poisoning_risk == "critical":
        p = min(p, 30)
    elif poisoning_risk == "high":
        p = min(p, 55)
    return min(p, 100)


def upsert(c, finding_type, key, title, *, sectors, scale, evidence,
           asserted=None, rep_blind=False, has_malware=False, novel=False,
           sector_exclusive=False):
    """Record a candidate finding; returns (finding_id, transition)."""
    fid = make_id(finding_type, key)
    ts = now()
    row = c.execute("SELECT * FROM findings WHERE finding_id=?", (fid,)).fetchone()
    cost = FORGERY_COST.get(finding_type, "medium")

    if row is None:
        days = 1
        transition = "new"
        first = ts
    else:
        # A new calendar day of activity counts once.
        same_day = row["last_seen"][:10] == ts[:10]
        days = row["days_seen"] + (0 if same_day else 1)
        first = row["first_seen"]
        if row["status"] == "quiet":
            transition = "resurfaced"
        elif scale > row["scale"] * 1.25 and scale > row["scale"] + 2:
            transition = "escalated"
        else:
            transition = "active"

    unique_sources = (evidence.get("distinct_ips")
                      or evidence.get("unique_ips") or 1)
    prisk, pflags, pstrength = assess_poisoning(
        finding_type, scale, days, unique_sources, sectors,
        bool(asserted and any(asserted.values())))
    pri = score(finding_type, sectors, scale, days, rep_blind, has_malware,
                novel, sector_exclusive, prisk)
    conf = min(pri, CONFIDENCE_CEILING[cost])

    c.execute("""
      INSERT INTO findings (finding_id, finding_type, title, first_seen, last_seen,
        status, priority, confidence, forgery_cost, days_seen, scale, sectors,
        evidence, asserted, poisoning_risk, poisoning_flags, evidence_strength)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(finding_id) DO UPDATE SET
        last_seen=excluded.last_seen, status=excluded.status,
        priority=excluded.priority, confidence=excluded.confidence,
        days_seen=excluded.days_seen, scale=excluded.scale,
        sectors=excluded.sectors, evidence=excluded.evidence,
        asserted=excluded.asserted, title=excluded.title
    """, (fid, finding_type, title, first, ts, transition, pri, conf, cost,
          days, scale, json.dumps(sorted(sectors)),
          json.dumps(evidence), json.dumps(asserted or {}),
          prisk, json.dumps(pflags), pstrength))
    c.execute("INSERT INTO history VALUES (?,?,?,?,?,?)",
              (fid, ts, transition, pri, scale, transition))
    return fid, transition


def mark_quiet(c, seen_ids, days=2):
    """Findings not seen for `days` go quiet — the basis of 'still active'."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = c.execute(
        "SELECT finding_id FROM findings WHERE last_seen < ? AND status != 'quiet' "
        "AND status != 'closed'", (cutoff,)).fetchall()
    for r in rows:
        if r["finding_id"] in seen_ids:
            continue
        c.execute("UPDATE findings SET status='quiet' WHERE finding_id=?",
                  (r["finding_id"],))
        c.execute("INSERT INTO history VALUES (?,?,?,?,?,?)",
                  (r["finding_id"], now(), "quiet", None, None, "went quiet"))
    return len(rows)


def active_suppressions(c):
    return {r["finding_id"] for r in c.execute(
        "SELECT finding_id FROM findings WHERE disposition='suppressed' "
        "OR (suppressed_until IS NOT NULL AND suppressed_until > ?)", (now(),))}


def delta(c, hours=24):
    """What changed — the daily brief's entire content."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    sup = active_suppressions(c)
    out = {k: [] for k in ("new", "escalated", "resurfaced", "quiet",
                           "needs_review", "continuing")}
    for r in c.execute("SELECT * FROM findings ORDER BY priority DESC"):
        if r["finding_id"] in sup:
            continue
        item = {"id": r["finding_id"], "title": r["title"],
                "priority": r["priority"], "confidence": r["confidence"],
                "type": r["finding_type"], "days_seen": r["days_seen"],
                "sectors": json.loads(r["sectors"]), "scale": r["scale"]}
        recent = r["last_seen"] >= since
        if r["status"] in ("new", "escalated", "resurfaced") and recent:
            out[r["status"]].append(item)
        elif r["status"] == "quiet":
            out["quiet"].append(item)
        elif recent:
            out["continuing"].append(item)
        if (r["disposition"] == "unreviewed" and r["priority"] >= 50
                and r["status"] != "quiet"):
            out["needs_review"].append(item)
    out["suppressed_count"] = len(sup)
    return out


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    p = sub.add_parser("list"); p.add_argument("--status"); p.add_argument("--limit", type=int, default=30)
    p = sub.add_parser("show"); p.add_argument("id")
    p = sub.add_parser("set"); p.add_argument("id"); p.add_argument("disposition", choices=DISPOSITIONS); p.add_argument("--note", default="")
    p = sub.add_parser("suppress"); p.add_argument("id"); p.add_argument("--days", type=int, default=30); p.add_argument("--note", default="")
    p = sub.add_parser("delta"); p.add_argument("--hours", type=int, default=24); p.add_argument("--json", action="store_true")
    a = ap.parse_args()
    c = conn()

    if a.cmd == "init":
        print(f"registry ready at {DB}")

    elif a.cmd == "list":
        q = "SELECT * FROM findings"
        args = ()
        if a.status:
            q += " WHERE status=?"; args = (a.status,)
        q += " ORDER BY priority DESC LIMIT ?"
        rows = c.execute(q, args + (a.limit,)).fetchall()
        if not rows:
            print("no findings"); return
        print(f"{'id':<18}{'pri':>4}{'conf':>5}  {'status':<11}{'days':>5}  title")
        for r in rows:
            print(f"{r['finding_id']:<18}{r['priority']:>4}{r['confidence']:>5}  "
                  f"{r['status']:<11}{r['days_seen']:>5}  {r['title'][:60]}")

    elif a.cmd == "show":
        r = c.execute("SELECT * FROM findings WHERE finding_id=?", (a.id,)).fetchone()
        if not r:
            print("not found"); sys.exit(1)
        for k in r.keys():
            v = r[k]
            if k in ("evidence", "asserted") and v:
                print(f"{k}:"); print("  " + json.dumps(json.loads(v), indent=2)[:1500])
            else:
                print(f"{k}: {v}")
        print("\nhistory:")
        for h in c.execute("SELECT * FROM history WHERE finding_id=? ORDER BY ts", (a.id,)):
            print(f"  {h['ts']}  {h['event']:<12} pri={h['priority']} scale={h['scale']}")

    elif a.cmd == "set":
        c.execute("UPDATE findings SET disposition=?, notes=?, reviewed_at=?, "
                  "reviewed_by=? WHERE finding_id=?",
                  (a.disposition, a.note, now(), os.environ.get("USER", "operator"), a.id))
        c.execute("INSERT INTO history VALUES (?,?,?,?,?,?)",
                  (a.id, now(), None, None, None, f"disposition={a.disposition}"))
        c.commit(); print(f"{a.id} -> {a.disposition}")

    elif a.cmd == "suppress":
        until = (datetime.now(timezone.utc) + timedelta(days=a.days)).isoformat()
        c.execute("UPDATE findings SET disposition='suppressed', suppressed_until=?, "
                  "notes=? WHERE finding_id=?", (until, a.note, a.id))
        c.execute("INSERT INTO history VALUES (?,?,?,?,?,?)",
                  (a.id, now(), None, None, None, f"suppressed {a.days}d"))
        c.commit(); print(f"{a.id} suppressed until {until[:10]}")

    elif a.cmd == "delta":
        d = delta(c, a.hours)
        if a.json:
            print(json.dumps(d, indent=1)); return
        for k in ("new", "escalated", "resurfaced", "needs_review", "quiet"):
            if d[k]:
                print(f"\n{k.upper()} ({len(d[k])})")
                for i in d[k][:10]:
                    print(f"  [{i['priority']:>3}] {i['id']}  {i['title'][:64]}")
        print(f"\ncontinuing: {len(d['continuing'])}  suppressed: {d['suppressed_count']}")
    c.commit()


if __name__ == "__main__":
    main()
