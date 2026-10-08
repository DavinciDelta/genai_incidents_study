"""feas_A_validation.py — Claim A: does the channel association survive codings that do not use the corpus attack vector?

A1  what rank-validation's hand labeller and its three LLM pre-labellers were shown (no corpus labels; channel visible in text?)
A2  hand labels mapped to an AI-is-target (ON side) / AI-is-instrument (WITH side) reading, x channel, ALL hand-labelled records
    (every step-2 population; 'no entry fits' and the entries that cannot be placed stay in the table), raw and quota-weighted;
    final labels and the blind first-read labels
A3  same, restricted to step-2 frame records, and step-2 population x hand side agreement
A4  step 2 re-run with the corpus attack_vector blanked (text + record type only)
A5  step 4 reviewed labels: no-attacker and misplaced-CVE records out (reviewers were LLMs that saw corpus labels)
Run: .venv/bin/python feas_A_validation.py  (from any directory; writes feas_A_validation.json next to this file)
"""
import collections, json, math, re
from feas_lib import (REPO, CH, FRAME, load_all, load_rv, join_rv, load_prelabels, classify, reviewed_pop, metrics, line, HEAD, dump)

C, S, P = load_all()
rv = load_rv(); J = join_rv(C, rv)
pct = lambda a, b: f"{100*a/b:.1f}%" if b else "—"
out = {}

# ------------------------------------------------------------------ A1 provenance
CYC = REPO / "external/incident-rank-validation/projects/owasp-llm/cycles/2026/calibration"
pre_rows = [json.loads(l) for l in open(CYC / "llm_prelabels.jsonl")]
pre_txt = {d["incident_id"]: d.get("text", "") for d in pre_rows}
LABEL_TOKENS = re.compile(r"attack[_ ]vector|owasp|\bLLM(0\d|10)\b|\bASI\d|AML\.T|mitre atlas", re.I)
adj_src = (REPO / "external/incident-rank-validation/tools/adjudicate.py").read_text()
prompt_src = (REPO / "external/incident-rank-validation/engine/classify/stage2_prompt.py").read_text()
gold_ids = list(rv["gold"])
print("# A1. What the hand labeller and the three LLM pre-labellers saw\n")
print(f"- pre-label rows {len(pre_rows):,}; hand-labelled (gold) rows {len(gold_ids):,}, all {sum(i in pre_txt for i in gold_ids):,} present in the pre-label file with their text.")
print(f"- tools/adjudicate.py prints: hashed id (sha256[:8]) {'yes' if 'sha256(iid' in adj_src else 'NO'}, triage tier, record['text']; asks the blind label "
      f"{'BEFORE' if adj_src.index('Your label') < adj_src.index('LLM consensus') else 'AFTER'} printing the LLM consensus and the three votes + rationales.")
print(f"- stage-2 prompt user message carries only the incident text: {'incident_text=_neutralize_delimiters(incident.text)' in prompt_src}; "
      "IncidentRecord.text = title + description + impact (engine/adapters/genai_agentic.py).")
tok = [i for i in gold_ids if LABEL_TOKENS.search(pre_txt[i])]
print(f"- gold texts containing a corpus-label token (attack_vector / OWASP / LLM0x / ASI / AML.T / MITRE ATLAS): {len(tok)} of {len(gold_ids):,}"
      + (f" (e.g. {tok[:3]})" if tok else ""))
vis = collections.Counter(); visn = collections.Counter()
for cur, row in J["rows"].items():
    if row["gold_labels"] is None: continue
    ch = S[cur]["source_class"]; visn[ch] += 1
    visn_t = pre_txt.get(row["snapshot_id"], "")
    if re.search(r"\bCVE-\d{4}-\d+|\bGHSA-", visn_t): vis[ch] += 1
print("- channel visible in the text the labeller read (a CVE or GHSA id in title/description), by current channel: "
      + "; ".join(f"{ch} {vis[ch]}/{visn[ch]} ({pct(vis[ch], visn[ch])})" for ch in CH))
out["A1"] = {"prelabel_rows": len(pre_rows), "gold_rows": len(gold_ids), "label_tokens_in_gold_text": len(tok),
             "cve_id_visible": {ch: [vis[ch], visn[ch]] for ch in CH}}

# ------------------------------------------------------------------ hand-label side mapping (this study's mapping, not the labeller's)
ON_E = {"LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM10", "NEW-PMP", "NEW-MTIE", "NEW-ITSCD",
        "ROLL-CMSB", "ROLL-LAPTF", "ROLL-CFAS"}                    # the AI system / its supply chain is what is attacked or fails
WITH_E = {"NEW-WLA"}                                                # Weaponized LLM Abuse: "the LLM is attack infrastructure, not the target"
FAIL_E = {"NEW-MA", "NEW-MSDA", "ROLL-SICG"}                       # adversary-optional model behaviour: no side
AMB_E = {"LLM09"}                                                  # Misinformation: hallucination (no attacker) or AI-made deception (WITH)
assert ON_E | WITH_E | FAIL_E | AMB_E == set(rv["taxonomy"]), set(rv["taxonomy"]) ^ (ON_E | WITH_E | FAIL_E | AMB_E)
SIDES = ("ON side", "WITH side", "both sides", "Misinformation (side unknown)", "model behaviour (no side)", "no entry fits")

def side(labels, broad=False):
    if not labels: return "no entry fits"
    with_set = WITH_E | (AMB_E if broad else set())
    s = {"ON" if e in ON_E else "WITH" if e in with_set else "AMB" if e in AMB_E else "FAIL" for e in labels}
    if "ON" in s and "WITH" in s: return "both sides"
    if "ON" in s: return "ON side"
    if "WITH" in s: return "WITH side"
    if "AMB" in s: return "Misinformation (side unknown)"
    return "model behaviour (no side)"

def blind_labels(snap):
    b = rv["gold"][snap].get("blind_label")
    return [] if b in (None, "out-of-scope", "skip", "") else [b]

# quota weights: hand-labelled rows were drawn per (triage tier, LLM consensus) stratum; weight = stratum size / rows drawn
PL = load_prelabels()
N_str = collections.Counter((d["triage_tier"], d["consensus"]) for d in PL.values())
n_str = collections.Counter((PL[i]["triage_tier"], PL[i]["consensus"]) for i in gold_ids)
wt = lambda snap: N_str[(PL[snap]["triage_tier"], PL[snap]["consensus"])] / n_str[(PL[snap]["triage_tier"], PL[snap]["consensus"])]

H = [(cur, row) for cur, row in J["rows"].items() if row["gold_labels"] is not None]
print(f"\nHand-labelled current records: {len(H):,} (of {len(gold_ids):,} gold rows; the rest collapsed onto the same current record or did not resolve). "
      f"Quota weights: {len(N_str)} (tier, consensus) strata over {len(PL):,} pre-labelled rows; weights range {min(wt(r['snapshot_id']) for _, r in H):.2f}–{max(wt(r['snapshot_id']) for _, r in H):.2f}.")

def side_table(title, recs, labf, weighted=False, broad=False, key="A2"):
    t = collections.defaultdict(collections.Counter)
    for cur, row in recs:
        w = wt(row["snapshot_id"]) if weighted else 1
        t[S[cur]["source_class"]][side(labf(row), broad)] += w
    print(f"\n## {title}\n")
    print("| channel | n | " + " | ".join(SIDES) + " | ON share of ON+WITH (definite sides only) |")
    print("|---|---|" + "---|" * len(SIDES) + "---|")
    tot = collections.Counter()
    for ch in CH:
        n = sum(t[ch].values()); tot.update(t[ch])
        on, wi = t[ch]["ON side"], t[ch]["WITH side"]
        print(f"| {ch} | {n:,.0f} | " + " | ".join(f"{t[ch][s]:,.0f} ({pct(t[ch][s], n)})" for s in SIDES) + f" | {pct(on, on + wi)} ({on:,.0f}/{on + wi:,.0f}) |")
    n = sum(tot.values()); on, wi = tot["ON side"], tot["WITH side"]
    print(f"| all | {n:,.0f} | " + " | ".join(f"{tot[s]:,.0f} ({pct(tot[s], n)})" for s in SIDES) + f" | {pct(on, on + wi)} ({on:,.0f}/{on + wi:,.0f}) |")
    m = metrics((ch, {"ON side": "ON-AI", "WITH side": "WITH-AI", "both sides": "BOTH"}.get(s, s), v) for ch in CH for s, v in t[ch].items())
    print(f"\nCramér's V, channel x (ON side, WITH side): {m['V']:.2f}")
    out.setdefault(key, {})[title] = {ch: dict(t[ch]) for ch in CH} | {"V": m["V"]}
    return t

fin = lambda row: row["gold_labels"]
blind = lambda row: blind_labels(row["snapshot_id"])
print("\n# A2. Hand labels read as ON side / WITH side, by channel — ALL hand-labelled records (every step-2 population)")
print("\nMapping (this study's, not the labeller's): ON side = the 15 entries where the AI system or its supply chain is attacked or fails "
      "(Prompt Injection ... Compositional Fine-tuning Alignment Subversion); WITH side = Weaponized LLM Abuse; Misinformation can be either "
      "(hallucination or AI-made deception) and is kept as its own column; Model Misalignment, Model Scheming, Systemic Insecure Code Generation "
      "need no adversary and have no side; 'no entry fits' is kept as a column.")
side_table("A2a. Final hand labels, unweighted", H, fin)
side_table("A2b. Final hand labels, quota-weighted (each row stands for its pre-label stratum)", H, fin, weighted=True)
side_table("A2c. Blind first-read labels (before the LLM votes were shown), unweighted", H, blind)
side_table("A2d. Final hand labels, broad mapping (Misinformation counted WITH side), unweighted", H, fin, broad=True)

# ------------------------------------------------------------------ A3 frame-only + agreement with step 2
HF = [(c, r) for c, r in H if S[c]["population"] in FRAME]
print(f"\n# A3. Restricted to step-2 frame records ({len(HF)} hand-labelled), and agreement with step 2")
side_table("A3a. Final hand labels, frame records only", HF, fin, key="A3")
ag = collections.defaultdict(collections.Counter)
for c, r in H: ag[S[c]["population"]][side(r["gold_labels"])] += 1
print("\n**A3b. Step-2 population x hand side (all hand-labelled records)**\n")
print("| step-2 population | n | " + " | ".join(SIDES) + " |"); print("|---|---|" + "---|" * len(SIDES))
for p in ("ON-AI", "WITH-AI", "BOTH", "UNRESOLVED", "NONE"):
    n = sum(ag[p].values()); print(f"| {p} | {n} | " + " | ".join(f"{ag[p][s]} ({pct(ag[p][s], n)})" for s in SIDES) + " |")
dON = ag["ON-AI"]["ON side"] + ag["ON-AI"]["WITH side"]; dWI = ag["WITH-AI"]["ON side"] + ag["WITH-AI"]["WITH side"]
print(f"\nWhere the hand label has a definite side: step-2 ON-AI records read ON side {ag['ON-AI']['ON side']}/{dON} ({pct(ag['ON-AI']['ON side'], dON)}); "
      f"step-2 WITH-AI records read WITH side {ag['WITH-AI']['WITH side']}/{dWI} ({pct(ag['WITH-AI']['WITH side'], dWI)}).")
def kappa(a, b, c, d):
    """Cohen's kappa for a 2x2 [[a, b], [c, d]] (rows step 2 ON/WITH, cols hand ON/WITH)."""
    n = a + b + c + d; po = (a + d) / n; pe = ((a + b) * (a + c) + (c + d) * (b + d)) / n / n
    return (po - pe) / (1 - pe)
k = kappa(ag["ON-AI"]["ON side"], ag["ON-AI"]["WITH side"], ag["WITH-AI"]["ON side"], ag["WITH-AI"]["WITH side"])
agb = collections.defaultdict(collections.Counter)
for c, r in H: agb[S[c]["population"]][side(blind_labels(r["snapshot_id"]))] += 1
kb = kappa(agb["ON-AI"]["ON side"], agb["ON-AI"]["WITH side"], agb["WITH-AI"]["ON side"], agb["WITH-AI"]["WITH side"])
nd = dON + dWI; nb = sum(agb[p]["ON side"] + agb[p]["WITH side"] for p in ("ON-AI", "WITH-AI"))
print(f"Cohen's kappa, step-2 ON/WITH vs hand side, on the {nd} of {sum(ag['ON-AI'].values()) + sum(ag['WITH-AI'].values())} step-2 ON/WITH hand-labelled records with a definite side: {k:.2f} (final labels); "
      f"{kb:.2f} on {nb} records (blind first-read labels).")
hdb_on = [(c, r) for c, r in H if S[c]["source_class"] == "harm-db" and side(r["gold_labels"]) == "ON side"]
print(f"harm-db records read ON side ({len(hdb_on)}): step-2 populations {dict(collections.Counter(S[c]['population'] for c, _ in hdb_on))} — "
      "mostly records with no adversary (an AI failure such as Sensitive Information Disclosure or Excessive Agency), which the OWASP list codes but ON/WITH does not.")
out["A3"]["agreement"] = {p: dict(ag[p]) for p in ag}; out["A3"]["kappa"] = {"final": [k, nd], "blind": [kb, nb]}

# ------------------------------------------------------------------ A4 text-only re-split
T = {i: classify(C[i], use_vector=False) for i in C}
print("\n# A4. Step 2 re-run with the corpus attack_vector blanked (text + record type decide)\n")
cross = collections.Counter((S[i]["population"], T[i][0]) for i in C)
pops = ("ON-AI", "WITH-AI", "BOTH", "UNRESOLVED", "NONE")
print("| with vector \\ text only | " + " | ".join(pops) + " |"); print("|---|" + "---|" * len(pops))
for a in pops: print(f"| {a} | " + " | ".join(f"{cross[(a, b)]:,}" for b in pops) + " |")
print(f"\nSame population: {sum(cross[(p, p)] for p in pops):,} of {len(C):,} ({pct(sum(cross[(p, p)] for p in pops), len(C))}).")
print("\n" + "\n".join(HEAD))
m0 = metrics((S[i]["source_class"], S[i]["population"], 1) for i in C)
m1 = metrics((S[i]["source_class"], T[i][0], 1) for i in C)
print(line("step 2 as published (vector + text)", m0)); print(line("text + record type only (vector blanked)", m1))
both_on = sum(S[i]["population"] == "ON-AI" and T[i][0] == "ON-AI" for i in C); both_wi = sum(S[i]["population"] == "WITH-AI" and T[i][0] == "WITH-AI" for i in C)
mv = metrics((S[i]["source_class"], S[i]["population"] if S[i]["population"] == T[i][0] else "dropped", 1) for i in C)
print(line("records both codings agree on only", mv))
out["A4"] = {"cross": {f"{a}->{b}": v for (a, b), v in cross.items()}, "published": m0, "text_only": m1, "agree_only": mv}

# ------------------------------------------------------------------ A5 reviewed step-4 labels
print("\n# A5. After step 4's review (two LLM reviewers + adjudicator per label; they saw the corpus labels)\n")
print("\n".join(HEAD))
m2 = metrics((S[i]["source_class"], reviewed_pop(i, S, P), 1) for i in C)
m3 = metrics((S[i]["source_class"], reviewed_pop(i, S, P, leak_to_with=True), 1) for i in C)
print(line("step 2 as published", m0)); print(line("reviewed: no-attacker and misplaced-CVE records out", m2))
print(line("reviewed + ON-AI records the review placed outside every ON value (entry point and target 'other') moved to WITH-AI", m3))
rc = collections.Counter((S[i]["source_class"], reviewed_pop(i, S, P)) for i in C if S[i]["population"] in ("ON-AI", "WITH-AI"))
print("\nRecords the review took out, by channel: " + "; ".join(
    f"{ch}: no attacker {rc[(ch, 'NONE (review)')]}, misplaced CVE {rc[(ch, 'CVE misplaced (review)')]}" for ch in CH))
leak = [i for i in P if S[i]["population"] == "ON-AI" and P[i]["entry_point_post"] == "other" and P[i]["target_post"].startswith("other")]
lp = re.compile(r"not an? AI|no AI system|not AI|attacker'?s? (own )?tool|criminals' tool|as (a|the) tool|victims? (are|is) not|not the target|abused, not attacked|is the attacker|instrument|WITH-AI|against ordinary victims|AI assisted", re.I)
print(f"ON-AI 'other/other' records: {len(leak)} ({collections.Counter(S[i]['source_class'] for i in leak)}); review note says the AI was the tool / no AI system attacked on {sum(bool(lp.search(P[i]['coded_note'])) for i in leak)} of {len(leak)}.")
out["A5"] = {"reviewed": m2, "reviewed_leak": m3}
dump("feas_A_validation.json", out)
