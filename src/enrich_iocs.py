#!/usr/bin/env python3
"""Submit novel honeypot IOCs from T-Pot to IntelOwl for enrichment.

Deterministic: no LLM in this path. Pulls top source IPs and file hashes from
Elasticsearch, skips anything already seen (local sqlite ledger), submits the
remainder to IntelOwl, and writes results to JSON for the report stage.

Usage:
  enrich_iocs.py [--hours 24] [--max-ips 25] [--dry-run]
"""
import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ES = "http://10.0.0.75:64298"
INTELOWL = "http://127.0.0.1:80"
LEDGER = "/home/mike/reports/ioc_ledger.sqlite"
OUT_DIR = "/home/mike/reports/enrichment"

# Private/reserved ranges and our own infrastructure are never submitted.
SKIP_PREFIXES = ("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.",
                 "172.19.", "172.2", "172.30.", "172.31.", "169.254.")


def token():
    with open("/home/mike/.intelowl_token") as f:
        return f.read().strip()


def es_search(body, index="logstash-*"):
    req = urllib.request.Request(
        f"{ES}/{index}/_search", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def collect_iocs(hours, max_ips):
    rng = {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
    r = es_search({
        "size": 0, "query": {"bool": {"filter": [rng]}},
        "aggs": {"ips": {"terms": {"field": "src_ip.keyword", "size": max_ips * 2}}}})
    ips = [b["key"] for b in r["aggregations"]["ips"]["buckets"]
           if not b["key"].startswith(SKIP_PREFIXES)][:max_ips]

    r = es_search({
        "size": 0,
        "query": {"bool": {"filter": [rng, {"exists": {"field": "shasum"}}]}},
        "aggs": {"h": {"terms": {"field": "shasum.keyword", "size": 25}}}})
    hashes = [b["key"] for b in r["aggregations"]["h"]["buckets"]]
    return ips, hashes


def ledger_conn():
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    c = sqlite3.connect(LEDGER)
    c.execute("""CREATE TABLE IF NOT EXISTS seen (
                   ioc TEXT PRIMARY KEY, kind TEXT, first_seen TEXT, job_id INTEGER)""")
    return c


def submit(observable, classification):
    body = json.dumps({
        "observables": [[classification, observable]],
        "tlp": "AMBER",
    }).encode()
    req = urllib.request.Request(
        f"{INTELOWL}/api/analyze_multiple_observables", data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Token {token()}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            resp = json.load(r)
        results = resp.get("results", [])
        return results[0].get("job_id") if results else None
    except urllib.error.HTTPError as e:
        print(f"  ! {observable}: HTTP {e.code} {e.read()[:200]}", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--max-ips", type=int, default=25)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    ips, hashes = collect_iocs(args.hours, args.max_ips)
    conn = ledger_conn()
    seen = {r[0] for r in conn.execute("SELECT ioc FROM seen")}

    novel = [(i, "ip") for i in ips if i not in seen]
    novel += [(h, "hash") for h in hashes if h not in seen]

    print(f"collected {len(ips)} IPs + {len(hashes)} hashes; "
          f"{len(novel)} novel, {len(ips) + len(hashes) - len(novel)} already enriched")
    if args.dry_run:
        for ioc, kind in novel:
            print(f"  would submit [{kind}] {ioc}")
        return

    submitted = []
    now = datetime.now(timezone.utc).isoformat()
    for ioc, kind in novel:
        job_id = submit(ioc, kind)
        if job_id:
            conn.execute("INSERT OR REPLACE INTO seen VALUES (?,?,?,?)",
                         (ioc, kind, now, job_id))
            conn.commit()
            submitted.append({"ioc": ioc, "kind": kind, "job_id": job_id})
            print(f"  + [{kind}] {ioc} -> job {job_id}")
        time.sleep(1)  # be gentle with analyzer rate limits

    os.makedirs(OUT_DIR, exist_ok=True)
    out = f"{OUT_DIR}/{datetime.now(timezone.utc).date()}-submissions.json"
    with open(out, "w") as f:
        json.dump(submitted, f, indent=1)
    print(f"wrote {out} ({len(submitted)} jobs)")


if __name__ == "__main__":
    main()
