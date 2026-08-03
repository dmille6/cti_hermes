#!/usr/bin/env python3
"""Load analyzer API keys into IntelOwl's plugin-config store.

Reads KEY=VALUE pairs from ~/io_keys.env (chmod 600, deleted after use) and
writes them as PluginConfig rows via the Django ORM inside the uwsgi container.
GreyNoise is deliberately excluded — subscription lapsed.
"""
import os
import sys

KEYS_FILE = "/home/mike/io_keys.env"

# source env var -> (IntelOwl parameter name, analyzer config names)
MAPPING = {
    "OTX_API_KEY": ("api_key_name", ["OTXQuery", "OTX_Check_Hash", "OTX_Check_IP", "OTX_Check_Domain"]),
    "ABUSEIPDB_API_KEY": ("api_key_name", ["AbuseIPDB"]),
    "GTI_API_KEY": ("api_key_name", ["VirusTotal_v3_Get_Observable", "VirusTotal_v3_Intelligence_Search"]),
    "SHODAN_API_KEY": ("api_key_name", ["Shodan_Honeyscore", "Shodan_Search"]),
    "MALWAREBAZAAR_API_KEY": ("api_key_name", ["MalwareBazaar_Get_Observable"]),
    "MAXMIND_LICENSE_KEY": ("api_key_name", ["MaxMindGeoIP"]),
    "MISP_KEY": ("api_key_name", ["MISP"]),
    "MISP_URL": ("url_key_name", ["MISP"]),
    "CENSYS_API_ID": ("api_id_name", ["Censys_Search"]),
    "CENSYS_API_SECRET": ("api_secret_name", ["Censys_Search"]),
}


def load_keys():
    keys = {}
    with open(KEYS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            keys[k.strip()] = v.strip().strip('"').strip("'")
    return keys


def main():
    import django
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "intel_owl.settings")
    django.setup()
    from api_app.models import PluginConfig, Parameter
    from api_app.analyzers_manager.models import AnalyzerConfig

    owner = None  # None => default config visible to all users

    keys = load_keys()
    applied, skipped = [], []

    for env_name, (param_name, analyzers) in MAPPING.items():
        value = keys.get(env_name)
        if not value:
            skipped.append(f"{env_name} (not in keys file)")
            continue
        for analyzer in analyzers:
            ac = AnalyzerConfig.objects.filter(name=analyzer).first()
            if not ac:
                skipped.append(f"{analyzer} (no such analyzer)")
                continue
            p = Parameter.objects.filter(
                name=param_name, python_module=ac.python_module).first()
            if not p:
                skipped.append(f"{analyzer}.{param_name} (no such parameter)")
                continue
            obj, created = PluginConfig.objects.update_or_create(
                parameter=p, owner=owner, for_organization=False,
                analyzer_config=ac, defaults={"value": value},
            )
            applied.append(f"{analyzer}.{param_name} ({'new' if created else 'updated'})")

    print("APPLIED:")
    for a in sorted(set(applied)):
        print("  ", a)
    print("SKIPPED:")
    for s in sorted(set(skipped)):
        print("  ", s)


if __name__ == "__main__":
    main()
