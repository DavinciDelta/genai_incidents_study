#!/usr/bin/env python3
"""feas_D_goldset_channel.py — exploratory (2026-10-08). The incident-rank-validation gold set (1,200 records hand-labelled by one person
on the May 2026 snapshot of the same index), split by disclosure channel: how often the person's blind first read, made before seeing any
model vote, said 'out of scope' (no OWASP LLM entry fits). Reads the vendored snapshot for source ids and channel; read only, nothing run.
Output: explore/out/feas_D_goldset_channel.out.txt (stdout)."""
import collections, json, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(REPO))
from common import source_class
CYC = REPO / "external/incident-rank-validation/projects/owasp-llm/cycles"
snap = next((CYC / "2026/corpora/genai_agentic").glob("*/incidents.jsonl"))
recs = {r["id"]: r for r in map(json.loads, open(snap))}
gold = [json.loads(l) for l in open(CYC / "2026-rarr/calibration/adjudicated_goldset.jsonl")]
c = collections.defaultdict(collections.Counter)
for g in gold:
    r = recs.get(g["incident_id"]); ch = source_class(r) if r else "not in snapshot"
    c[ch]["rows"] += 1; c[ch]["blind out-of-scope"] += g["blind_label"] == "out-of-scope"; c[ch]["final no entry"] += g["labels"] == []
print(f"snapshot: {snap.parent.name[:12]}… ({len(recs):,} records); gold rows: {len(gold):,}\n")
print("| channel | gold rows | blind first read: out of scope | final label: no entry |\n|---|---|---|---|")
for ch in ("cve/ghsa", "harm-db", "research/other", "not in snapshot"):
    x = c[ch]
    if x["rows"]: print(f"| {ch} | {x['rows']:,} | {x['blind out-of-scope']:,} ({100*x['blind out-of-scope']/x['rows']:.0f}%) | {x['final no entry']:,} ({100*x['final no entry']/x['rows']:.0f}%) |")
