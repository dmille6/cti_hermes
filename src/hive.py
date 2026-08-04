#!/usr/bin/env python3
"""Hive Elasticsearch endpoint resolution.

The T-Pot hive has two addresses for the same cluster
(uuid ObLBKZ6ySXWsI1fI_n1y9w):

  10.0.0.75:64298    internal LAN — what ctihermes uses
  99.18.26.20:64298  external — what cti1 (76.165.200.190) uses

Neither is reachable from the other side, so the endpoint depends on where
the code runs. Resolve at runtime rather than hardcoding, so the same script
works from ctihermes, cti1, or anywhere else.

Override with CTI_ES_URL, or ~/etc/hive.json {"candidates": [...]}.
"""
import json
import os
import urllib.request

CONFIG = os.path.expanduser("~/etc/hive.json")
DEFAULT_CANDIDATES = ["http://10.0.0.75:64298", "http://99.18.26.20:64298"]
EXPECTED_CLUSTER_UUID = "ObLBKZ6ySXWsI1fI_n1y9w"

_resolved = None


def candidates():
    try:
        with open(CONFIG) as f:
            c = json.load(f).get("candidates")
            if c:
                return c
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return DEFAULT_CANDIDATES


def resolve(verify_cluster=True):
    """First reachable endpoint. Cached for the life of the process."""
    global _resolved
    if _resolved:
        return _resolved
    if os.environ.get("CTI_ES_URL"):
        _resolved = os.environ["CTI_ES_URL"].rstrip("/")
        return _resolved
    errors = []
    for url in candidates():
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                info = json.load(r)
            uuid = info.get("cluster_uuid")
            if verify_cluster and uuid != EXPECTED_CLUSTER_UUID:
                # A different cluster would silently produce a report about
                # the wrong population — refuse rather than mislead.
                errors.append(f"{url}: unexpected cluster_uuid {uuid}")
                continue
            _resolved = url.rstrip("/")
            return _resolved
        except Exception as e:
            errors.append(f"{url}: {type(e).__name__}")
    raise RuntimeError("no hive endpoint reachable — " + "; ".join(errors))


def search(body, index="logstash-*", timeout=120):
    req = urllib.request.Request(
        f"{resolve()}/{index}/_search", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


if __name__ == "__main__":
    print(resolve())
