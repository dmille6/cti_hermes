#!/usr/bin/env python3
"""Shared narrative-model client for the cti_hermes reporting scripts.

The reports make exactly ONE completion call each with a ~5-12K token prompt.
They use no tools, no memory and no skills, so they do not need an agent
framework — and going direct avoids Hermes Agent's 64K context floor, which
was the sole cause of the Ollama memory thrashing on the Studio (a 64K window
makes Ollama allocate a 4x KV cache, ~99 GB, which cannot coexist with the
~89 GB the tsec analytics tier pins).

Default target is qwen2.5:32b on the Studio because the tsec pipeline already
keeps it resident: zero contention, nothing gets evicted.

Override without touching code via ~/etc/llm.json:
    {"base_url": "...", "model": "...", "timeout": 900, "max_tokens": 1600}
or the CTI_LLM_URL / CTI_LLM_MODEL environment variables.
"""
import json
import os
import time
import urllib.error
import urllib.request

CONFIG = "/home/mike/etc/llm.json"

DEFAULTS = {
    "base_url": "http://76.165.200.8:11436/v1",
    "model": "qwen2.5:32b",
    "timeout": 900,
    "max_tokens": 1600,
    "temperature": 0.3,
}


def config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG) as f:
            cfg.update({k: v for k, v in json.load(f).items()
                        if not k.startswith("_")})
    except FileNotFoundError:
        pass
    if os.environ.get("CTI_LLM_URL"):
        cfg["base_url"] = os.environ["CTI_LLM_URL"]
    if os.environ.get("CTI_LLM_MODEL"):
        cfg["model"] = os.environ["CTI_LLM_MODEL"]
    return cfg


def narrate(prompt, required_marker=None, retries=1):
    """Return (text, meta). text is None if the call failed or looked wrong.

    required_marker: a string the response must contain (e.g. a section
    heading). Guards against a model that answered something unrelated.
    """
    cfg = config()
    body = json.dumps({
        "model": cfg["model"],
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": cfg["max_tokens"],
        "temperature": cfg["temperature"],
    }).encode()

    last_err = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            f"{cfg['base_url'].rstrip('/')}/chat/completions", data=body,
            headers={"Content-Type": "application/json"})
        t = time.time()
        try:
            with urllib.request.urlopen(req, timeout=cfg["timeout"]) as r:
                d = json.load(r)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = f"{type(e).__name__}: {e}"
            continue
        if "error" in d:
            last_err = str(d["error"])
            continue
        text = (d["choices"][0]["message"].get("content") or "").strip()
        meta = {"model": cfg["model"], "seconds": round(time.time() - t, 1),
                "usage": d.get("usage", {}), "attempt": attempt + 1}
        if required_marker and required_marker not in text:
            last_err = f"response missing required marker {required_marker!r}"
            continue
        return text, meta
    return None, {"model": cfg["model"], "error": last_err}
