# IntelOwl deployment (ctihermes, 2026-08-03)

IntelOwl **v6.7.0** running via Docker Compose on `ctihermes` (10.0.0.120).

## Access

- Web UI: `http://10.0.0.120/` (nginx on port 80)
- Admin user: `admin` / password in `~/.intelowl_admin_pw` on the VM (chmod 600)
- API token: `~/.intelowl_token` on the VM (chmod 600)

Containers: nginx, uwsgi, daphne, celery_worker_default, celery_beat,
postgres, redis. Managed from `~/intelowl`:

```
cd ~/intelowl && ./start prod up -- -d      # start
cd ~/intelowl && ./start prod down          # stop
```

## Install notes / gotchas

- `./initialize.sh` needs sudo (installs Docker + logrotate). Docker was
  already present, so we skipped it and copied the env templates by hand:
  `env_file_app`, `env_file_postgres`, `env_file_integrations`,
  `.env.start.test`. `DJANGO_SECRET`, `POSTGRES_PASSWORD`, and `DB_PASSWORD`
  were then generated with `secrets`.
- Superuser creation requires `--first_name`/`--last_name` with `--noinput`.
- **API tokens: IntelOwl uses DRF's `rest_framework.authtoken`, NOT durin.**
  Durin's `AuthToken` exists in the codebase and validates fine through the
  ORM, but `DEFAULT_AUTHENTICATION_CLASSES` is
  `rest_framework.authentication.TokenAuthentication`, so a durin token gets
  a flat `{"detail": "Invalid token."}` over HTTP. Create tokens with:
  `Token.objects.create(user=u)` from `rest_framework.authtoken.models`.
- Analyzer secrets live in the **database** (`PluginConfig`), not env files.
  `PluginConfig` requires exactly one of `analyzer_config` / `connector_config`
  / `visualizer_config` / `ingestor_config` / `pivot_config` to be set, or
  `clean_config()` raises "You must select a plugin configuration".
  `src/configure_intelowl.py` handles this.

## Configured analyzers

Loaded from the operator's `env/env` (gitignored) via
`src/configure_intelowl.py`, then the staging copy was deleted:

| Analyzer | Parameter | Status |
|---|---|---|
| AbuseIPDB | api_key_name | ✅ verified returning data |
| OTXQuery | api_key_name | ✅ verified returning pulses |
| OTX_Check_Hash | api_key_name | ✅ |
| VirusTotal_v3_Get_Observable | api_key_name (GTI key) | ✅ |
| VirusTotal_v3_Intelligence_Search | api_key_name (GTI key) | ✅ |
| Shodan_Honeyscore | api_key_name | ✅ |
| Shodan_Search | api_key_name | ✅ |
| MaxMindGeoIP | api_key_name | ✅ |
| MISP | api_key_name + url_key_name | ✅ |

**GreyNoise deliberately excluded** — operator's subscription lapsed.

Not configured:
- **Censys** — `CENSYS_API_ID` / `CENSYS_API_SECRET` are present but **empty**
  in `env/env`. Populate them there and re-run `configure_intelowl.py` to
  enable `Censys_Search`.
- **MalwareBazaar** — the analyzer exposes no `api_key_name` parameter in
  v6.7.0 (it works unauthenticated); the key in `env/env` is unused here.
- **CrowdStrike** — no IntelOwl analyzer; use `falcon-mcp` for Falcon intel.

## Enrichment bridge

`src/enrich_iocs.py` (deployed to `~/bin/enrich_iocs.py`) is the deterministic
ingest path — **no LLM in this flow**:

1. Aggregate top source IPs and file hashes from T-Pot ES over a time window.
2. Drop RFC1918/reserved ranges.
3. Skip anything already enriched (sqlite ledger at
   `~/reports/ioc_ledger.sqlite`) so repeat offenders don't burn API quota.
4. Submit the remainder to IntelOwl, one per second.
5. Write `~/reports/enrichment/YYYY-MM-DD-submissions.json` for the report
   stage to join against.

```bash
python3 ~/bin/enrich_iocs.py --dry-run --max-ips 5   # preview
python3 ~/bin/enrich_iocs.py --hours 24 --max-ips 25 # real run
```

## MISP integration (2026-08-03)

MISP **2.5.39** at `https://76.165.200.8:8443` (org TSEC, self-signed cert →
`verify_tls: false`). Credentials on the VM at `~/.misp.json` (chmod 600).
**123 warninglists, all enabled.**

Bulk filtering uses `POST /warninglists/checkValue` with a JSON array of
values — one request covers the whole batch and returns which lists matched.

### Filter chain in `enrich_iocs.py`

1. **Reserved/private** ranges — dropped.
2. **Own infrastructure** (`~/etc/homenet.json`) — dropped, never submitted
   anywhere. Seeded from `t-pot_ip_ext` values observed in Elasticsearch.
3. **MISP warninglists** — dropped, *except* lists named in
   `~/etc/warninglist_policy.json` under `annotate_only`.
4. **Ledger** (`~/reports/ioc_ledger.sqlite`) — already enriched, skipped.

### Why `annotate_only` exists

MISP's "vpn-ipv4 addresses belonging to common VPN providers and datacenters"
list matched 9 DigitalOcean IPs in the first live run. For a generic IOC feed
those are noise; for a **honeynet they are frequently real attackers** — VPS-
hosted scanners are the norm. So datacenter/VPN hits are recorded as context
in the submissions JSON but still get enriched. Everything else that hits a
warninglist is dropped.

Example configs live in `src/etc.example/` (the real ones hold secrets and
stay on the VM).

## First live enrichment run (2026-08-03)

34 jobs submitted (10 IPs + 24 hashes). Filters dropped: 1 own-infrastructure
IP (`76.165.200.190`, 340k events — operator-confirmed as theirs), 1 junk hash
(sha256 of the empty file). 6 datacenter IPs annotated but still enriched.

Analyzer status after fixes:

| Analyzer | Result |
|---|---|
| AbuseIPDB | ✅ working |
| OTXQuery | ✅ working (ip + hash) |
| VirusTotal_v3_Get_Observable | ✅ working (GTI key) |
| MISP | ✅ working after `ssl_check=False` + `self_signed_certificate=True` |
| MaxMindGeoIP | ✅ working (first runs fail while it downloads the GeoLite2 DBs) |
| Shodan_Search | ✅ working; 404 = Shodan has no data for that host (recorded as FAILED, normal) |
| Shodan_Honeyscore | ❌ retired upstream — `/labs/honeyscore/` always 400s. Do not use. |

### Submission gotcha

`analyzers_requested` **must** be specified. Omitting it returns
`400 {"errors":{"detail":["No Analyzers and Connectors can be run after
filtering:"]}}` — IntelOwl filters the default set down to nothing. See
`ANALYZERS` in `src/enrich_iocs.py`.

### Note

IntelOwl embeds API keys in analyzer error messages (e.g. the full Shodan URL
with `?key=...` appears in job error output). Treat job errors as sensitive;
don't paste them into tickets or share job JSON externally.

## Next

- Enable IntelOwl connectors to push results into MISP and OpenCTI.
- Join enrichment output into the daily brief.
