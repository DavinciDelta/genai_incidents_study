#!/usr/bin/env python3
"""fetch_data.py — pin and fetch the two external inputs this study reads.

1. Full genai_incidents JSON at the release tag matching the installed pip package
   (the pip package bundles only the slim incidents.min.json; the full file carries
   category, cwe_ids, source_ids and the references list).
2. rocklambros/incident-rank-validation at a pinned commit (shallow clone; we read its
   committed artifacts, we never run its engine).

3. For s05_techniques.py: the MITRE ATLAS release the corpus mapping is built on (its technique ->
   mitigation relationships), and the corpus's own build script at the same tag (read, never run: it
   holds the OWASP -> ATLAS back-fill table the corpus labels come from).

Writes external/incidents.json, external/mitre_atlas.json, the two OWASP name files, external/ATLAS.yaml,
external/corpus_merge_and_dedupe.py, external/incident-rank-validation/ and external/PINS.json with
sha256 of what was fetched. Re-run is idempotent.
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
ATLAS_COMMIT, ATLAS_RELEASE = "3259f388d19cbcca11bacf12a0ef97f4198f711b", "2026.06"   # mitre-atlas/atlas-data; release = mitre_atlas.json atlas_data_version
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def get(url, dst):
    if dst.exists(): return
    print("fetch", url); urllib.request.urlretrieve(url, dst)

get(f"{RAW}/data/incidents.json", EXT / "incidents.json")
get(f"{RAW}/mappings/mitre_atlas.json", EXT / "mitre_atlas.json")
for f in ("owasp_llm_top10_2026.json", "owasp_asi_top10.json"): get(f"{RAW}/mappings/{f}", EXT / f)   # code names, corpus numbering
get(f"{RAW}/scripts/merge_and_dedupe.py", EXT / "corpus_merge_and_dedupe.py")
get(f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/{ATLAS_COMMIT}/dist/v6/ATLAS-{ATLAS_RELEASE}.yaml", EXT / "ATLAS.yaml")
rv = EXT / "incident-rank-validation"
if not rv.exists():
    subprocess.run(["git", "clone", "-q", "--filter=blob:none", RV_REPO, str(rv)], check=True)
    subprocess.run(["git", "-C", str(rv), "checkout", "-q", RV_COMMIT], check=True)

pins = {"genai_incidents_pip": PKG_VERSION, "genai_incidents_tag": TAG,
        "incidents_json_sha256": sha(EXT / "incidents.json"),
        "incident_rank_validation_commit": RV_COMMIT,
        "atlas_data_commit": ATLAS_COMMIT, "atlas_release": ATLAS_RELEASE, "atlas_yaml_sha256": sha(EXT / "ATLAS.yaml"),
        "corpus_merge_script_sha256": sha(EXT / "corpus_merge_and_dedupe.py")}
(EXT / "PINS.json").write_text(json.dumps(pins, indent=1))
print(json.dumps(pins, indent=1))
