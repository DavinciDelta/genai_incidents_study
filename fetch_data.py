#!/usr/bin/env python3
"""fetch_data.py — pin and fetch the two external inputs this study reads.

1. Full genai_incidents JSON at the release tag matching the installed pip package
   (the pip package bundles only the slim incidents.min.json; the full file carries
   category, cwe_ids, source_ids and the references list).
2. rocklambros/incident-rank-validation at a pinned commit (shallow clone; we read its
   committed artifacts, we never run its engine).

Writes external/incidents.json, external/mitre_atlas.json, external/incident-rank-validation/
and external/PINS.json with sha256 of what was fetched. Re-run is idempotent.
"""
import hashlib, json, subprocess, sys, urllib.request
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXT = ROOT / "external"; EXT.mkdir(exist_ok=True)
PKG_VERSION = version("genai-incidents")
TAG = f"v{PKG_VERSION}"
RAW = f"https://raw.githubusercontent.com/emmanuelgjr/genai_incidents/{TAG}"
RV_REPO = "https://github.com/rocklambros/incident-rank-validation"
RV_COMMIT = "f7a92a1a5bf21066f49d94a3335c6f66269f3e67"

def get(url, dst):
    if dst.exists(): return
    print("fetch", url); urllib.request.urlretrieve(url, dst)

get(f"{RAW}/data/incidents.json", EXT / "incidents.json")
get(f"{RAW}/mappings/mitre_atlas.json", EXT / "mitre_atlas.json")
rv = EXT / "incident-rank-validation"
if not rv.exists():
    subprocess.run(["git", "clone", "-q", "--filter=blob:none", RV_REPO, str(rv)], check=True)
    subprocess.run(["git", "-C", str(rv), "checkout", "-q", RV_COMMIT], check=True)

pins = {"genai_incidents_pip": PKG_VERSION, "genai_incidents_tag": TAG,
        "incidents_json_sha256": hashlib.sha256((EXT / "incidents.json").read_bytes()).hexdigest(),
        "incident_rank_validation_commit": RV_COMMIT}
(EXT / "PINS.json").write_text(json.dumps(pins, indent=1))
print(json.dumps(pins, indent=1))
