#!/usr/bin/env python3
"""Submit novel honeypot IOCs from T-Pot to IntelOwl for enrichment.

Deterministic: no LLM in this path. Pulls top source IPs and file hashes from
Elasticsearch, applies three filters, submits the remainder to IntelOwl, and
records what was sent.

Filter order (cheapest and most important first):
  1. Reserved/private ranges           — never useful
  2. Own infrastructure (homenet.yml)  — NEVER report yourself to the community
  3. MISP warninglists                 — known-benign (DNS resolvers, CDNs, ...)
  4. Already-enriched ledger           — don't re-burn API quota

Usage:
  enrich_iocs.py [--hours 24] [--max-ips 25] [--dry-run] [--no-warninglists]
"""
import argparse
import ipaddress
import json
import os
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ES = "http://10.0.0.75:64298"
INTELOWL = "http://127.0.0.1:80"
LEDGER = "/home/mike/reports/ioc_ledger.sqlite"
OUT_DIR = "/home/mike/reports/enrichment"
HOMENET = "/home/mike/etc/homenet.json"
MISP_CONF = "/home/mike/.misp.json"   # {"url": ..., "key": ..., "verify_tls": false}
WL_POLICY = "/home/mike/etc/warninglist_policy.json"

# Warninglists whose hits are recorded but NOT dropped. Datacenter/VPS ranges
# are the classic case: MISP flags them as common false positives for generic
# IOC feeds, but for a honeynet they are frequently real attacker infra.
DEFAULT_ANNOTATE_ONLY = ["vpn-ipv4", "datacenter", "VPN providers"]

# Analyzers to run per observable type. Must be explicit — see submit().
ANALYZERS = {
    # Shodan_Search, not Shodan_Honeyscore — the /labs/honeyscore/ endpoint is
    # retired and always 400s. Shodan_Search 404s when Shodan simply has no
    # data for a host, which IntelOwl records as FAILED; that is normal.
    "ip": ["AbuseIPDB", "OTXQuery", "Shodan_Search", "MaxMindGeoIP",
           "VirusTotal_v3_Get_Observable", "MISP"],
    "hash": ["OTXQuery", "VirusTotal_v3_Get_Observable", "MISP"],
}

# Hashes of empty/trivial files that honeypots capture constantly. Enriching
# these wastes quota and pollutes reports.
JUNK_HASHES = {
    # sha256 / sha1 / md5 of the empty file
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "d41d8cd98f00b204e9800998ecf8427e",
}

_NOVERIFY = ssl.create_default_context()
_NOVERIFY.check_hostname = False
_NOVERIFY.verify_mode = ssl.CERT_NONE


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        if default is None:
            raise
        return default


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
        "aggs": {"ips": {"terms": {"field": "src_ip.keyword", "size": max_ips * 3}}}})
    ips = [(b["key"], b["doc_count"]) for b in r["aggregations"]["ips"]["buckets"]]

    r = es_search({
        "size": 0,
        "query": {"bool": {"filter": [rng, {"exists": {"field": "shasum"}}]}},
        "aggs": {"h": {"terms": {"field": "shasum.keyword", "size": 25}}}})
    hashes = [(b["key"], b["doc_count"]) for b in r["aggregations"]["h"]["buckets"]]
    return ips, hashes


def is_reserved(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not an IP at all -> don't submit
    return (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast
            or a.is_link_local or a.is_unspecified)


def load_homenet():
    """Networks and IPs belonging to the operator. Never submitted anywhere."""
    conf = read_json(HOMENET, default={"networks": [], "ips": []})
    nets = [ipaddress.ip_network(n, strict=False) for n in conf.get("networks", [])]
    ips = set(conf.get("ips", []))
    return nets, ips


def is_own(ip, nets, ips):
    if ip in ips:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def misp_warninglist_hits(values):
    """Return {value: [warninglist names]} for values matching any MISP warninglist."""
    conf = read_json(MISP_CONF, default=None)
    if not conf:
        print("  (no MISP config; skipping warninglist filter)", file=sys.stderr)
        return {}
    req = urllib.request.Request(
        f"{conf['url'].rstrip('/')}/warninglists/checkValue",
        data=json.dumps(list(values)).encode(),
        headers={"Authorization": conf["key"], "Accept": "application/json",
                 "Content-Type": "application/json"})
    ctx = None if conf.get("verify_tls") else _NOVERIFY
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            data = json.load(r)
    except Exception as e:
        print(f"  ! MISP warninglist check failed ({e}); not filtering", file=sys.stderr)
        return {}
    return {v: [w.get("name") for w in hits] for v, hits in data.items() if hits}


def ledger_conn():
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    c = sqlite3.connect(LEDGER)
    c.execute("""CREATE TABLE IF NOT EXISTS seen (
                   ioc TEXT PRIMARY KEY, kind TEXT, first_seen TEXT, job_id INTEGER)""")
    return c


def submit(observable, classification):
    # IntelOwl runs nothing if analyzers_requested is omitted ("No Analyzers
    # and Connectors can be run after filtering"), so name them explicitly.
    body = json.dumps({
        "observable_name": observable,
        "observable_classification": classification,
        "analyzers_requested": ANALYZERS[classification],
        "tlp": "AMBER",
    }).encode()
    req = urllib.request.Request(
        f"{INTELOWL}/api/analyze_observable", data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Token {token()}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r).get("job_id")
    except urllib.error.HTTPError as e:
        print(f"  ! {observable}: HTTP {e.code} {e.read()[:200]}", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--max-ips", type=int, default=25)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-warninglists", action="store_true")
    args = ap.parse_args()

    raw_ips, hashes = collect_iocs(args.hours, args.max_ips)
    nets, own_ips = load_homenet()

    dropped = {"reserved": [], "own": [], "warninglist": [], "junk_hash": [],
               "ledger": []}
    candidates = []
    for ip, count in raw_ips:
        if is_reserved(ip):
            dropped["reserved"].append(ip)
        elif is_own(ip, nets, own_ips):
            dropped["own"].append(f"{ip} ({count} events)")
        else:
            candidates.append(ip)
    candidates = candidates[:args.max_ips]

    annotations = {}
    if candidates and not args.no_warninglists:
        policy = read_json(WL_POLICY, default={})
        annotate_only = policy.get("annotate_only", DEFAULT_ANNOTATE_ONLY)
        hits = misp_warninglist_hits(candidates)
        drop_set = set()
        for ip, names in hits.items():
            soft = [n for n in names
                    if any(pat.lower() in (n or "").lower() for pat in annotate_only)]
            if len(soft) == len(names):
                # every match was annotate-only -> keep, but record the context
                annotations[ip] = names
            else:
                drop_set.add(ip)
                dropped["warninglist"].append(f"{ip} [{', '.join(names[:2])}]")
        candidates = [ip for ip in candidates if ip not in drop_set]
        for ip, names in annotations.items():
            print(f"  note [datacenter/VPN, still submitting]: {ip} [{names[0]}]")

    conn = ledger_conn()
    seen = {r[0] for r in conn.execute("SELECT ioc FROM seen")}
    novel = [ip for ip in candidates if ip not in seen]
    dropped["ledger"] = [ip for ip in candidates if ip in seen]

    dropped["junk_hash"] = [h for h, _ in hashes if h in JUNK_HASHES]
    real_hashes = [h for h, _ in hashes if h not in JUNK_HASHES]
    novel_hashes = [h for h in real_hashes if h not in seen]
    dropped["ledger"] += [h for h in real_hashes if h in seen]

    print(f"collected {len(raw_ips)} IPs + {len(hashes)} hashes")
    for reason, items in dropped.items():
        if items:
            print(f"  dropped [{reason}]: {len(items)}")
            for i in items[:5]:
                print(f"      {i}")
            if len(items) > 5:
                print(f"      ... and {len(items) - 5} more")
    print(f"  submitting: {len(novel)} IPs + {len(novel_hashes)} hashes")

    if args.dry_run:
        for x in novel + novel_hashes:
            print(f"  would submit {x}")
        return

    submitted = []
    now = datetime.now(timezone.utc).isoformat()
    for ioc, kind in [(i, "ip") for i in novel] + [(h, "hash") for h in novel_hashes]:
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
        json.dump({"submitted": submitted, "dropped": dropped,
                   "warninglist_annotations": annotations}, f, indent=1)
    print(f"wrote {out} ({len(submitted)} jobs)")


if __name__ == "__main__":
    main()
