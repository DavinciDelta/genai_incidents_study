#!/usr/bin/env python3
"""s01_overview.py — Step 1. What the data is, general breakdowns, and what the
incident-rank-validation artifacts show. NO dissection into ON-AI / WITH-AI here.

Part A runs the README usage snippet from github.com/emmanuelgjr/genai_incidents verbatim.
Part B profiles the full corpus. Part C reads incident-rank-validation's committed artifacts.
Output: out/s01_overview.md
"""
import collections, json
from importlib.metadata import version
from genai_incidents import query, by_cve, resolve_id            # README snippet imports
from common import load_full, load_rv, join_rv, beta_mean, source_class, table, write, EXT

L = [f"# Step 1 — Overview (genai-incidents {version('genai-incidents')}, full JSON sha256 {json.load(open(EXT/'PINS.json'))['incidents_json_sha256'][:12]}…)"]

# ---------------- A. README snippet, verbatim
L += ["", "## A. README usage snippet (package API)", "", "```"]
for inc in query(severity="Critical", attack_vector="prompt-injection", year=2026):
    L.append(f'{inc["id"]} - {inc["title"]}')
L.append(f'by_cve("CVE-2026-21520") -> {[i["id"] for i in by_cve("CVE-2026-21520")]}')
L.append(f'resolve_id("INC-00139") -> {resolve_id("INC-00139")}')
L.append("```")

# ---------------- B. general corpus profile (full JSON)
C = load_full(); R = list(C.values()); n = len(R)
L += ["", "## B. What the data is", "",
      f"- Records: **{n:,}**; landmark tier: **{sum(r['tier']=='landmark' for r in R):,}**; years {min(r['year'] for r in R)}–{max(r['year'] for r in R)}",
      f"- Records with a CVE: {sum(bool(r.get('cve_ids')) for r in R):,}; with a CWE: {sum(bool(r.get('cwe_ids')) for r in R):,}; merged from >1 source: {sum(len(r['source_ids'])>1 for r in R):,}",
      f"- Median description length: {sorted(len(r.get('description') or '') for r in R)[n//2]} chars"]
L += table("Source (prefix of source_ids; a record may carry several)", [s for r in R for s in r["source_ids"]], lambda s: s.split("-")[0], top=10)
L += table("Disclosure channel (derived)", R, source_class)
L += table("Category", R, lambda r: r["category"])
L += table("Tier", R, lambda r: r["tier"]); L += table("Quality tier", R, lambda r: r["quality_tier"]); L += table("Corpus", R, lambda r: r.get("corpus"))
L += table("Record year (2019+)", [r for r in R if r["year"] >= 2019], lambda r: r["year"], top=10, note="record year is ingestion-affected")
L += ["", "## B2. General breakdowns", ""]
L += table("attack_vector", R, lambda r: r.get("attack_vector") or "other", top=15)
L += table("severity", R, lambda r: r["severity"])
L += table("OWASP LLM Top 10 (2026) codes — a record may carry several", [c for r in R for c in (r.get("owasp_llm") or [])], lambda c: c)
L += table("OWASP Agentic (ASI) codes", [c for r in R for c in (r.get("owasp_asi") or [])], lambda c: c)
L += table("CWE (top)", [c for r in R for c in (r.get("cwe_ids") or [])], lambda c: c, top=10)
L += ["", "> Labels above are the corpus's own heuristic assignments (see its DATASHEET). They describe what the", "> heuristics matched, not measured prevalence."]

# ---------------- C. incident-rank-validation artifacts
rv = load_rv(); J = join_rv(C, rv); JR = J["rows"]
L += ["", "## C. What incident-rank-validation shows about this data", "",
      f"- Snapshot: 7,714 records (May 2026); **{len(JR):,}** resolve to a current record, {len(J['unresolved'])} do not.",
      f"- Label source: stage-1 rules {sum(r['rv_stage']==1 for r in JR.values()):,}, stage-2 LLM {sum(r['rv_stage']==2 for r in JR.values()):,}.",
      f"- Gold set: {len(rv['gold']):,} hand-adjudicated rows; adjudicator overrode the model on {sum(g['adjudicated']=='override' for g in rv['gold'].values()):,}; "
      f"out of scope (no entry applies): {sum(g['labels']==[] for g in rv['gold'].values()):,}.",
      f"- Headline: weighted κ vote-vs-data = {rv['concordance'].get('weighted_kappa_median', 0):.3f}; frame-blind entries: LLM04, LLM08, LLM10."]
lab = collections.Counter(e for r in JR.values() for e in r["rv_entries"]); gold = collections.Counter(e for r in JR.values() for e in (r["gold_labels"] or []))
L += ["", "**Vote rank vs data rank vs share of records, per entry** (sorted by vote rank)", "",
      "| Entry | Name | Vote rank | Data rank (90% CI) | % of classifier labels | % of gold labels | Recall | Precision | n gold |", "|---|---|---|---|---|---|---|---|---|"]
for e, t in sorted(rv["taxonomy"].items(), key=lambda kv: rv["ranks"].get(kv[0], {}).get("vote_rank", 99)):
    rk = rv["ranks"].get(e, {}); lo, hi = rk.get("lambda_ci", (0, 0))
    rc, nr = beta_mean(rv["posteriors"], "recall", e); pr, _ = beta_mean(rv["posteriors"], "precision", e)
    L.append(f"| {e} | {t['canonical_name']} | {rk.get('vote_rank','?'):g} | {rk.get('lambda_rank','?'):g} ({lo:g}–{hi:g}) | {100*lab[e]/sum(lab.values()):.1f} | {100*gold[e]/sum(gold.values()):.1f} | {rc:.2f} | {pr:.2f} | {nr} |")
L += ["", "**Where the gold-set out-of-scope rows come from**", ""]
oos = [C[i] for i, r in JR.items() if r["gold_labels"] == []]
L += table("source class of out-of-scope rows", oos, source_class)
L += table("attack_vector of out-of-scope rows", oos, lambda r: r.get("attack_vector") or "other", top=6)
write("s01_overview.md", L)
