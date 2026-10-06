#!/usr/bin/env python3
"""s05_techniques.py — Step 5. Two questions: (1) which OWASP categories stand out in each population against the community vote,
checked against one person's hand labels; (2) which MITRE ATLAS mitigations address the ON-AI categories and which labelled techniques
have none (after Hamer et al., "Closing the Chain", arXiv:2503.12192). Runs last, so it also hosts the study's Use cases and
Limitations of the data. Step 4 answers HOW attacks happened; this file does not repeat it.

Everything here is a corpus keyword label or a read of another project's artifacts; nothing is coded from reports yet.
llm(), asi() and techs() are where hand codes replace the corpus labels in the next phase.
Output: out/s05_techniques.md
"""
import ast, collections, json, math, re
from common import (load_full, load_atlas, load_rv, join_rv, load_prelabels, owasp_names, blind_agreement, source_class, text, write,
                    READ, OUT, EXT, CYCLE, CHANNELS)

S = json.load(open(OUT / "split.json")); C = load_full(); R = list(C.values()); A = load_atlas(); REF = json.load(open(EXT / "mitre_atlas.json"))
PINS = json.load(open(EXT / "PINS.json")); rv = load_rv(); JR = join_rv(C, rv); J = JR["rows"]; PRE = load_prelabels()
NM = owasp_names(rv); NAME = {**NM["corpus"], **NM["asi"]}; RV2C, C2RV, RVN = NM["rv2corpus"], NM["corpus2rv"], NM["rv"]
POPS = ("ON-AI", "WITH-AI"); P = {p: [C[i] for i, s in S.items() if s["population"] == p] for p in POPS}
DEMO = ("research", "research-demonstrated", "red-team")
GAP = 3              # corpus rank and vote rank 'disagree' from this many places apart
MIN_RECORDS = 30     # below this many corpus records a category is 'too few records'
MARKER_SHARE = 0.9   # a code is a channel marker when it sits on this share of one channel's records, or of its own assignments
SMALL = 10           # 'person kept the corpus label' needs this many hand-labelled rows carrying the code
MIN_HAND = 2         # a proposed addition gets its own row from this many hand labels; MIN_BULLET its own bullet
WIDE = 10            # a data-rank interval spanning this many places is 'wide' (limitations)
MIN_BULLET, MAX_BULLETS, TOP_MIT, TOP_GAP, MAX_NAMES = 5, 5, 10, 6, 3
WLA, MIS = next(e for e, n in RVN.items() if n == "Weaponized LLM Abuse"), next(e for e, n in RVN.items() if n == "Misinformation")
BLIND = sorted(e for e, x in json.load(open(CYCLE / "calibration/diagnostic.json"))["entry_reports"].items() if "frame-blind" in x["reason"])

def llm(r): return r.get("owasp_llm") or []              # <- hand codes replace these three after the coding phase
def asi(r): return r.get("owasp_asi") or []
def techs(r): return r.get("mitre_atlas") or []
def ename(c): return RVN[C2RV[c]] if c in C2RV else NAME[c]    # rank-validation's entry name for an OWASP LLM code, the corpus's for an ASI code
def code(c): return f"{ename(c)} [{c}]"
def parent(t): return t.rsplit(".", 1)[0] if t.count(".") == 2 else t
def tname(t): return (A["techniques"].get(t) or REF["techniques"].get(t) or {}).get("name", "?")
def label(t): return f"{t} {tname(t)}"
def tactics(t): return [REF["tactics"][x]["name"] for x in (REF["techniques"].get(t) or {}).get("tactics") or (REF["techniques"].get(parent(t)) or {}).get("tactics") or []]
def mits(t): return A["mitigates"].get(t, set()) | A["mitigates"].get(parent(t), set())    # a sub-technique inherits its parent's mitigations
def attack_ref(t): return (A["techniques"].get(t) or {}).get("attack_ref") or (A["techniques"].get(parent(t)) or {}).get("attack_ref")
def pc(a, b, d=1): return f"{100*a/b:.{d}f}" if b else "—"
def npc(a, b): return f"{a:,} ({pc(a, b)}%)"
def ranks(counter): return {k: 1 + sum(w > v for w in counter.values()) for k, v in counter.items() if v}    # ties share a rank
def median(xs): xs = sorted(xs); return xs[len(xs) // 2] if xs else 0
def uniq(xs): return list(dict.fromkeys(xs))
def chan(rows): return {x: [r for r in rows if source_class(r) == x] for x in CHANNELS}
def ch_cells(hits, by_ch): return " | ".join(pc(sum(hits(r) for r in by_ch[x]), len(by_ch[x])) for x in CHANNELS)
def few(names, k=MAX_NAMES): return ", ".join(names[:k]) + (f" +{len(names) - k}" if len(names) > k else "") if names else "—"
def head(num, title, n, desc, cols): return ["", f"**Table {num}. {title}** ({n})", ""] + ([desc, ""] if desc else []) + ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
def mname(m): return f"{m} {M[m]['name']}"

def vote_ci():
    """Vote-rank 90% intervals from rank-validation's rank_comparison_report.md (load_rv parses the line but keeps only the point rank)."""
    pat = re.compile(r"^\|\s*([A-Z0-9-]+)\s*\|[^|]*\|\s*([\d.]+) \(([\d.]+)[–-]([\d.]+)\)")
    return {m.group(1): (float(m.group(3)), float(m.group(4))) for l in open(CYCLE / "results/rank_comparison_report.md") if (m := pat.match(l.strip()))}
VCI = vote_ci(); VR = {e: rv["ranks"][e]["vote_rank"] for e in rv["ranks"]}

def build_tables():
    """OWASP code -> ATLAS technique lookup and attack_vector -> OWASP seed, read (never run) from the corpus's build script."""
    out = {}
    for node in ast.parse((EXT / "corpus_merge_and_dedupe.py").read_text()).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") in ("LLM_TO_ATLAS", "ASI_TO_ATLAS", "_VECTOR_TO_OWASP_LLM"):
            out[node.targets[0].id] = ast.literal_eval(node.value)
    return {**out["LLM_TO_ATLAS"], **out["ASI_TO_ATLAS"]}, out["_VECTOR_TO_OWASP_LLM"]
XW, SEED = build_tables()
# A lookup link this study judges wrong (a recorded judgement, not a measurement; edit here). The mitigation tables drop the technique labels it alone produces.
SUSPECT = {"LLM07": "misinformation is not model poisoning"}
def backfill(r, skip=()): return {t for c in llm(r) + asi(r) if c not in skip for t in XW.get(c, [])}
def sound(r): return set(techs(r)) - (backfill(r) - backfill(r, SUSPECT))
def via(t): return [c for c in sorted(XW, key=lambda c: (c[:3] != "LLM", c)) if t in XW[c]]
def seed_share(rows):
    lab = [(r, c) for r in rows for c in llm(r)]; return sum(c in SEED.get(r.get("attack_vector") or "", []) for r, c in lab), len(lab)
def rep(rows): return sum(len(set(techs(r)) & backfill(r)) for r in rows), sum(len(set(techs(r))) for r in rows)
def trio(f): return " / ".join(f"{pc(*f(rows))}%" for rows in (R, P["ON-AI"], P["WITH-AI"]))
SUS_T = XW["LLM07"][0]; dropped = {p: sum(len(set(techs(r)) - sound(r)) for r in P[p]) for p in POPS}

# hand-labelled rows per population: (id, record, label list in rank-validation ids; [] = no entry fits)
GOLD = {p: [(i, C[i], J[i]["gold_labels"]) for i, s in S.items() if s["population"] == p and i in J and J[i]["gold_labels"] is not None] for p in POPS}
def hand_counts(G): return collections.Counter(e for _, _, gl in G for e in gl), sum(gl == [] for _, _, gl in G)
def outcome(gl): return "no entry" if gl == [] else ("Misinformation" if MIS in gl else ("Weaponized LLM Abuse" if WLA in gl else "other entry"))
def tier_of(i): return (PRE.get(J[i]["snapshot_id"]) or {}).get("triage_tier")
KAPPA, KCI = rv["concordance"]["weighted_kappa_median"], rv["concordance"]["weighted_kappa_ci"]
def sg(x): return f"{x:.2f}".replace("-", "−")
cve_all = [r for r in R if source_class(r) == "cve/ghsa"]; sc_cve = sum("LLM04" in llm(r) for r in cve_all)
METH = json.load(open(OUT / "methodology.json")) if (OUT / "methodology.json").exists() else None
ENTRIES = sorted(rv["ranks"], key=lambda e: (VR[e], e)); ADDS = [e for e in ENTRIES if e not in RV2C]
GW, n_wi = GOLD["WITH-AI"], len(GOLD["WITH-AI"]); w_none = sum(gl == [] for _, _, gl in GW)
ON = P["ON-AI"]; n_on = len(ON); on_ch = chan(ON); M = A["mitigations"]
CNT = {p: collections.Counter(t for r in P[p] for t in sound(r)) for p in POPS}
def reach(p): return sum(any(mits(t) for t in sound(r)) for r in P[p])
HUM = {p: hand_counts(GOLD[p]) for p in POPS}
gold_ids = set(rv["gold"]); g_rec = sum(v["gold_labels"] is not None for v in J.values())
quota = collections.Counter((PRE[i]["consensus"], PRE[i]["agreement"]) for i in gold_ids if i in PRE and PRE[i]["triage_tier"] != "disagree" and PRE[i]["consensus"] != "out-of-scope")
cap = {a: max(v for (c, aa), v in quota.items() if aa == a) for a in ("3-of-3", "2-of-3")}    # the per-entry quota, recovered as the largest cell

# ---------------------------------------------------------------- opener
L = ["# Step 5 — Which attack categories stand out against the expert vote, and which ATLAS mitigations address them", "",
     f"Generated by `s05_techniques.py` (`make s05`); do not edit by hand; inputs pinned in `external/PINS.json`. {READ} Limitations: Table 5.7.", "",
     f"Two questions: which OWASP LLM Top 10 categories stand out in each population against the OWASP community vote, checked against one person's hand labels; "
     f"and which MITRE ATLAS mitigations address the ON-AI categories, and which labelled techniques have none. Three sources: the corpus's categories are keyword labels, "
     f"not coded fields; the hand labels are one person's verdicts on a quota sample ({len(GOLD['ON-AI'])} ON-AI and {n_wi} WITH-AI of the {g_rec:,} hand-labelled records "
     f"that join; the rest are BOTH, UNRESOLVED or NONE), so no CI and no ranking; the vote and its 90% interval are rank-validation's (its data rank and verdict: Table 1.15). "
     f"Step 4 answers how the attacks happened and is not repeated; names are rank-validation's entry names, corpus code in brackets."]

# ---------------------------------------------------------------- Tables 5.1 / 5.2
ALL_CH = chan(R)
def marker_why(c):
    tot = sum(c in llm(r) for r in R)
    for x, ch in ALL_CH.items():
        k = sum(c in llm(r) for r in ch)
        if k >= MARKER_SHARE * len(ch): return f"{ename(c)} on {pc(k, len(ch))}% of {x} records"
        if k >= MARKER_SHARE * tot: return f"{pc(k, tot)}% of {ename(c)} labels from {x}"
MARKER = {c: w for c in NM["corpus"] if (w := marker_why(c))}
L += ["", "## Which categories stand out?", "",
      f"Not a prevalence ranking or a corrected Top 10: corpus labels are keyword rules that mark the channel more than the content ({ename('LLM04')} sits on "
      f"{pc(sc_cve, len(cve_all))}% of CVE/GHSA records), the hand-labelled rows are a quota sample, and the vote is {len(ENTRIES)} candidates ranked by respondents.", "",
      f"*Flag key.* agree = corpus rank within {GAP - 1} places of the vote rank (the vote spans {len(ENTRIES)} candidates, the corpus ten coded entries); corpus above / vote above = "
      f"{GAP}+ places apart; too few records = under {MIN_RECORDS} corpus records; channel marker = {MARKER_SHARE:.0%}+ of one channel's records carry the code or "
      f"{MARKER_SHARE:.0%}+ of its labels come from one channel ({'; '.join(MARKER[c] for c in sorted(MARKER))}). Hand-label counts are capped by the "
      f"{cap['3-of-3']} + {cap['2-of-3']} per-entry quota and the all-disagree-rows rule: read them against the corpus column of the same row only."]
def flag(e, c, cnt, crank):
    if c is None: return "no corpus label"
    if cnt[c] < MIN_RECORDS: return "too few records"
    f = "corpus above vote" if VR[e] - crank[c] >= GAP else ("vote above corpus" if crank[c] - VR[e] >= GAP else "agree")
    return f + (" (channel marker)" if c in MARKER else "")

def category_table(p, num):
    rows, n = P[p], len(P[p]); G = GOLD[p]; ng = len(G); on = p == "ON-AI"
    cnt = collections.Counter(c for r in rows for c in set(llm(r))); crank = ranks(cnt); hum, none = HUM[p]
    shown = [e for e in ENTRIES if e in RV2C or hum[e] >= MIN_HAND]; pooled = [e for e in ADDS if e not in shown]
    fl = {e: flag(e, RV2C.get(e), cnt, crank) for e in ENTRIES}
    k = sum(fl[e].startswith(("corpus above", "vote above")) for e in RV2C); m = sum(e in shown for e in ADDS)
    kept = {}
    for e, c in RV2C.items():
        carry = [gl for _, r, gl in G if c in llm(r)]; kept[e] = (sum(e in gl for gl in carry), len(carry))
    cols = ["category [corpus code]", "vote rank (90% interval)", "corpus records n (%)", "corpus rank"] + (["demonstrated, % of the code's records"] if on else []) \
           + [f"hand labels (of {ng})", "person kept corpus label", "flag"]
    L.extend(head(num, f"{p}: {k} of ten categories sit {GAP}+ places from their vote rank; {m} proposed additions draw hand labels without a corpus code",
                  f"n = {n:,} {p} records; {ng} hand-labelled",
                  (f"*Corpus rank* orders the ten categories by {p} records carrying the code; *demonstrated* = research, research-demonstrated or red-team (glossary); "
                   f"*kept* = of the hand-labelled rows the corpus coded with this entry, how many the person filed under the same entry (shown from {SMALL} such rows); "
                   f"† = frame-blind (glossary).") if on else "Columns as in Table 5.1.", cols))
    for e in shown:
        c = RV2C.get(e); lo, hi = VCI[e]; agree, carry = kept.get(e, (0, 0))
        kp = f"{agree} of {carry} ({pc(agree, carry, 0)}%)" if carry >= SMALL else "—"
        demo = [pc(sum(r["category"] in DEMO for r in rows if c in llm(r)), cnt[c], 0) if c and cnt[c] else "—"] if on else []
        L.append(f"| {code(c) if c else RVN[e] + ' [proposed]'}{'†' if e in BLIND else ''} | {VR[e]:g} ({lo:g}–{hi:g}) | {npc(cnt[c], n) if c else '—'} | {crank.get(c, '—') if c else '—'} | "
                 + "".join(f"{d} | " for d in demo) + f"{hum[e]} | {kp} | {fl[e]} |")
    L.append(f"| *{len(pooled)} other proposed additions* | {min(VR[e] for e in pooled):g}–{max(VR[e] for e in pooled):g} | — | — | " + ("— | " if on else "") + f"{sum(hum[e] for e in pooled)} | — | — |")
    L.append(f"| *No entry fits* | — | — | — | " + ("— | " if on else "") + f"{none} ({pc(none, ng)}%) | — | — |")
    flagged = sorted((e for e in RV2C if fl[e].startswith(("corpus above", "vote above"))), key=lambda e: -abs(VR[e] - crank[RV2C[e]]))
    adds = sorted((e for e in ADDS if hum[e] >= MIN_BULLET), key=lambda e: -hum[e])
    bullets, q = [], [flagged, adds]
    while len(bullets) < MAX_BULLETS - 1 and any(q):
        for src in q:
            if src and len(bullets) < MAX_BULLETS - 1:
                e = src.pop(0); c = RV2C.get(e)
                if c:
                    agree, carry = kept[e]
                    bullets.append(f"- {RVN[e]}: corpus rank {crank[c]}, vote rank {VR[e]:g}" + (", channel marker" if c in MARKER else "")
                                   + (f"; code kept on {agree} of {carry} rows" if carry >= SMALL else f"; {carry} hand-labelled rows carry the code"))
                else:
                    on_rows = [r for _, r, gl in G if e in gl]; cc = collections.Counter(x for r in on_rows for x in llm(r)); chs = collections.Counter(source_class(r) for r in on_rows)
                    bullets.append(f"- {RVN[e]}: no corpus code; {hum[e]} hand labels (corpus codes there: {', '.join(f'{ename(x)} {v}' for x, v in cc.most_common(2))}; "
                                   f"{chs.most_common(1)[0][1]} {chs.most_common(1)[0][0]}); vote rank {VR[e]:g}")
    shares = sorted(((100 * a / b, e) for e, (a, b) in kept.items() if b >= SMALL), key=lambda x: x[0]); top = shares[-1]
    L.extend(["", "What stands out:", ""] + bullets + [f"- No entry fits: {npc(none, ng)} of the {ng} hand-labelled {p} records", "",
              f"On the {len(shares)} coded categories with {SMALL}+ hand-labelled rows the person kept the corpus label on {shares[0][0]:.0f}–{shares[-2][0]:.0f}% of rows "
              f"({top[0]:.0f}% for {RVN[top[1]]})" + (": corpus rank orders keyword hits, not what the record describes." if on else ".")])
    return cnt, crank, hum, none, kept, shares
cnt_on, crank_on, hum_on, none_on, kept_on, sh_on = category_table("ON-AI", "5.1")
land = [(RVN[e], HUM["WITH-AI"][0][e]) for e in ENTRIES if HUM["WITH-AI"][0][e] >= MIN_BULLET]
L += ["", f"The OWASP list scopes LLM applications, so WITH-AI records (the AI is the attacker's instrument) are expected to fall outside it; Table 5.2 shows where they land: "
      + ", ".join(f"{n} ({v})" for n, v in sorted(land, key=lambda x: -x[1])) + f", or no entry ({w_none})."]
_, crank_wi, hum_wi, none_wi, kept_wi, _ = category_table("WITH-AI", "5.2")

# ---------------------------------------------------------------- the no-entry paragraph and Table 5.3
pool = {p: [i for i, s in S.items() if s["population"] == p and i in J and tier_of(i)] for p in POPS}
TIERS = (("disagree", "disagree"), ("split", "two agree"), ("agree", "three agree"))
dis = {p: [x for x in GOLD[p] if tier_of(x[0]) == "disagree"] for p in POPS}
none_t = {t: (sum(gl == [] for i, _, gl in GW if tier_of(i) == t), sum(tier_of(i) == t for i, _, _ in GW)) for t, _ in TIERS}
taken_t = {t: (sum(tier_of(i) == t for i, _, _ in GW), sum(tier_of(i) == t for i in pool["WITH-AI"])) for t, _ in TIERS}
taken_other = [taken_t[t][0] / max(1, taken_t[t][1]) for t in ("split", "agree")]
dfk = [gl for _, r, gl in GW if r.get("attack_vector") == "deepfake"]; dfo = collections.Counter(outcome(gl) for gl in dfk)
L += ["", f"## Why {pc(w_none, n_wi, 0)}% of the hand-labelled WITH-AI records fit no category", "",
      f"{w_none} of {n_wi} hand-labelled WITH-AI records ({pc(w_none, n_wi)}%) fit no entry. Design: the sample took every "
      f"record the three LLM pre-labellers disagreed on ({len(dis['WITH-AI'])} of {n_wi}) but only {100*min(taken_other):.0f}–{100*max(taken_other):.0f}% of the "
      f"other rows; {none_t['disagree'][0]} of the {w_none} are such rows, and no entry runs {' / '.join(pc(*none_t[t], 0) + '%' for t, _ in TIERS)} across the "
      f"{' / '.join(tn for _, tn in TIERS)} tiers. Substance: every rubric entry requires an LLM mechanism, which deepfake fraud and abuse imagery lack: the "
      f"{len(dfk)} deepfake records among the {n_wi} split {dfo['no entry']} no entry / {dfo['Misinformation']} {RVN[MIS]} / {dfo['Weaponized LLM Abuse']} {RVN[WLA]} / "
      f"{dfo['other entry']} other. The share describes this sample only."]
L += head("5.3", f"No entry fits on {pc(*none_t['disagree'], 0)}% of WITH-AI rows the pre-labellers disagreed on, {pc(*none_t['agree'], 0)}% of those they agreed on",
          f"n = {len(GOLD['ON-AI'])} ON-AI and {n_wi} WITH-AI hand-labelled records",
          "Hand-labelled records by the three LLM pre-labellers' tier; the disagree tier was taken in full, the others by quota. The ON-AI no-entry records are listed by title in Table 4.7b.",
          ["population", "pre-label tier", "hand-labelled", "no entry fits n (%)", RVN[MIS], RVN[WLA], "other entry"])
for p in POPS:
    for t, tn in TIERS:
        o = collections.Counter(outcome(gl) for i, _, gl in GOLD[p] if tier_of(i) == t); g = sum(o.values())
        L.append(f"| {p} | {tn} | {g} | {npc(o['no entry'], g)} | {o['Misinformation']} | {o['Weaponized LLM Abuse']} | {o['other entry']} |")
no_tier = {p: sum(not tier_of(i) for i, _, _ in GOLD[p]) for p in POPS}
if any(no_tier.values()): L += ["", f"Rows without a pre-label tier are left out: {', '.join(f'{p} {v}' for p, v in no_tier.items() if v)}."]

# ---------------------------------------------------------------- ATLAS: Tables 5.4–5.6
imp = {p: sum(v for t, v in CNT[p].items() if "Impact" in tactics(t)) for p in POPS}; lab = {p: sum(CNT[p].values()) for p in POPS}
L += ["", "## Which ATLAS mitigations address the ON-AI categories, and which techniques have none", "",
      f"The chain is keyword OWASP code → the corpus's fixed lookup → ATLAS technique label → ATLAS's own technique → mitigation link (Table 5.A1); *addresses* means "
      f"that link exists, not that the control works or was deployed (ATLAS categories, lifecycle phases, tactics: glossary). WITH-AI is left out after Table 5.4: "
      f"{pc(imp['WITH-AI'], lab['WITH-AI'], 0)}% of its technique labels are Impact tactics, which name the harm rather than a step the attacker took and carry no mitigation, "
      f"so ATLAS reaches {pc(reach('WITH-AI'), len(P['WITH-AI']), 0)}% of WITH-AI records against {pc(reach('ON-AI'), n_on, 0)}% of ON-AI."]
L += head("5.4", f"{pc(reach('ON-AI'), n_on, 0)}% of ON-AI and {pc(reach('WITH-AI'), len(P['WITH-AI']), 0)}% of WITH-AI records carry a technique label that ATLAS links to a mitigation",
          f"n = {n_on:,} ON-AI and {len(P['WITH-AI']):,} WITH-AI records",
          f"Labels are (record, technique) pairs, less the {dropped['ON-AI']:,} ON-AI and {dropped['WITH-AI']:,} WITH-AI labels produced only by the {ename('LLM07')} → {tname(SUS_T)} link, "
          f"judged unsound (Table 5.A1, note 1); a mitigation counts if ATLAS links it to the technique or its parent.",
          ["measure", *POPS])
def measure(name, f): L.append(f"| {name} | " + " | ".join(f(p) for p in POPS) + " |")
measure("records with at least one technique label", lambda p: npc(sum(bool(sound(r)) for r in P[p]), len(P[p])))
measure("records with at least one technique that has an ATLAS mitigation", lambda p: npc(reach(p), len(P[p])))
measure("technique labels with an ATLAS mitigation", lambda p: npc(sum(v for t, v in CNT[p].items() if mits(t)), lab[p]))
measure("technique labels on Impact-tactic techniques", lambda p: npc(imp[p], lab[p]))

hit = {m: frozenset(t for t in CNT["ON-AI"] if m in mits(t)) for m in M}
groups = collections.defaultdict(list)
for m in M:
    if hit[m]: groups[hit[m]].append(m)
cov = {hs: [r for r in ON if sound(r) & hs] for hs in groups}
ranked = sorted(groups, key=lambda hs: (-len(cov[hs]), -len(hs), sorted(groups[hs])))
def gname(hs): return " / ".join(M[m]["name"] for m in sorted(groups[hs]))
def gshort(hs): g = sorted(groups[hs]); return M[g[0]]["name"] + (f" (+{len(g) - 1})" if len(g) > 1 else "")
def reached(hs): return few([ename(c) for c in sorted(XW, key=lambda c: (c[:3] != "LLM", c)) if c not in SUSPECT and any(t in hs for t in XW[c])], 2)
def ch_share(hs, x): return sum(source_class(r) == x for r in cov[hs]) / len(on_ch[x])
def via_t(hs): return few(sorted(hs, key=lambda t: -CNT["ON-AI"][t]), 2)
g0, top, rest = ranked[0], ranked[:TOP_MIT], ranked[TOP_MIT:]
second = {x: max(ranked[1:], key=lambda hs: (ch_share(hs, x), -ranked.index(hs))) for x in CHANNELS}
L += head("5.5", f"ON-AI: ATLAS links {gname(g0)} to technique labels on {pc(len(cov[g0]), n_on, 0)}% of records; next " + ", ".join(f"{gshort(second[x])} in {x}" for x in CHANNELS),
          f"n = {n_on:,} ON-AI records; {sum(len(v) for v in groups.values())} of {len(M)} ATLAS mitigations address at least one",
          f"ATLAS {PINS['atlas_release']}; mitigations linked to the same observed techniques share a row, the last row pools the rest; *via* = technique labels carrying the link "
          f"(names: Table 5.A1); *reached* = entries whose lookup technique the row addresses, Agentic Top 10 (ASI) included because the lookup maps both lists.",
          ["mitigation(s)", "kind (ATLAS category)", "ON-AI records addressed n (%)", "% in cve/ghsa", "% in harm-db", "% in research/other", "via technique(s)", "OWASP categories reached"])
for hs in top:
    ids = {id(r) for r in cov[hs]}
    L.append(f"| {'; '.join(mname(m) for m in sorted(groups[hs]))} | {', '.join(uniq(c for m in sorted(groups[hs]) for c in M[m]['categories']))} | {npc(len(cov[hs]), n_on)} | "
             + ch_cells(lambda r, ids=ids: id(r) in ids, on_ch) + f" | {via_t(hs)} | {reached(hs)} |")
if rest:
    rid = {id(r) for hs in rest for r in cov[hs]}; rn = sum(len(groups[hs]) for hs in rest)
    kinds = uniq(c for hs in rest for m in sorted(groups[hs]) for c in M[m]['categories']); kinds = "all three" if set(kinds) == {c for m in M for c in M[m]['categories']} else ', '.join(kinds)
    L.append(f"| *{rn} more mitigations, each addressing under {math.ceil(100 * max(len(cov[hs]) for hs in rest) / n_on)}% of records* | {kinds} | "
             f"{npc(len(rid), n_on)} | " + ch_cells(lambda r: id(r) in rid, on_ch) + f" | {via_t(frozenset().union(*rest))} | {reached(frozenset().union(*rest))} |")

gaps = sorted((t for t in CNT["ON-AI"] if not mits(t)), key=lambda t: (-CNT["ON-AI"][t], t)); top_g, rest_g = gaps[:TOP_GAP], gaps[TOP_GAP:]
def exists_in(t): return f"ATT&CK {attack_ref(t)}" if attack_ref(t) else ("none (Impact tactic)" if "Impact" in tactics(t) else "none")
L += head("5.6", f"ON-AI: the two most frequent technique labels, {tname(gaps[0]).lower()} ({pc(CNT['ON-AI'][gaps[0]], n_on, 0)}%) and {tname(gaps[1]).lower()} "
          f"({pc(CNT['ON-AI'][gaps[1]], n_on, 0)}%), have no ATLAS mitigation", f"n = {n_on:,} ON-AI records; {len(gaps)} unmitigated techniques, top {len(top_g)} shown",
          "Where ATLAS adapted the technique from ATT&CK, that catalogue has mitigations ATLAS did not import: a coverage gap, not the absence of a control. An Impact tactic names an outcome, not a control point.",
          ["technique", "ON-AI records n (%)", "% in cve/ghsa", "% in harm-db", "% in research/other", "OWASP codes the corpus lookup maps to it", "mitigation exists in"])
for t in top_g:
    L.append(f"| {label(t)} | {npc(CNT['ON-AI'][t], n_on)} | " + ch_cells(lambda r, t=t: t in sound(r), on_ch) + f" | {few([ename(c) for c in via(t)])} | {exists_in(t)} |")
if rest_g:
    rs = set(rest_g); rr = [r for r in ON if sound(r) & rs]
    L.append(f"| *{len(rest_g)} more techniques (pooled)* | {npc(len(rr), n_on)} | " + ch_cells(lambda r: bool(sound(r) & rs), on_ch) + " | — | — |")
g_src = [c for c in via(gaps[0]) if c in C2RV]
if g_src:
    a0, b0 = kept_on[C2RV[g_src[0]]]
    L += ["", f"The {CNT['ON-AI'][gaps[0]]:,} {tname(gaps[0])} labels are the image of the {code(g_src[0])} rule, which the person kept on {a0} of {b0} hand-labelled ON-AI rows "
          f"({pc(a0, b0, 0)}%): a label gap first, a framework gap second."]

# ---------------------------------------------------------------- Use cases
ioh, mcp = "LLM10", next(e for e, n in RVN.items() if n.startswith("MCP")); g0_ch = [100 * ch_share(g0, x) for x in CHANNELS]
agent = next(hs for hs in ranked if any("Human In-the-Loop" in M[m]["name"] for m in groups[hs]))
demo_on = {c: sum(r["category"] in DEMO for r in ON if c in llm(r)) / v for c, v in cnt_on.items() if v >= MIN_RECORDS}
lo_d, hi_d = min(demo_on, key=lambda c: (demo_on[c], c)), max(demo_on, key=lambda c: (demo_on[c], c))
top_hand = max((e for e in RV2C), key=lambda e: hum_on[e]); ka, kb = kept_on[top_hand]
L += ["", "## Use cases", "",
      f"- *Deployers of agents and copilots.* {ename(ioh)} (corpus rank {crank_on[ioh]}, vote {VR[C2RV[ioh]]:g}) and {RVN[mcp]} ({hum_on[mcp]} hand labels, no code) "
      f"stand out in ON-AI; ATLAS names no control for either: the first maps to {tname(gaps[0])} ({len(mits(gaps[0]))} ATLAS mitigations; ATT&CK {attack_ref(gaps[0])} has them), "
      f"the second has no lookup technique; ATLAS's agent controls (human in the loop, tool and permission limits) are linked to {pc(len(cov[agent]), n_on, 0)}% of records "
      f"(Tables 5.1, 5.5, 5.6). Caveat: keyword labels, kept on {pc(*kept_on[C2RV[ioh]], 0)}% of {ename(ioh)} rows.",
      f"- *Researchers.* {RVN[top_hand]}: most-used ON-AI hand label ({hum_on[top_hand]}), best-kept code ({pc(ka, kb, 0)}%), flagged 'agree'; "
      f"{ename(lo_d)}: realized, rarely demonstrated ({100*demo_on[lo_d]:.0f}%) (Table 5.1). "
      f"Caveat: 'demonstrated' tracks the research channel ({pc(sum(source_class(r) == 'research/other' for r in R), len(R), 0)}% of the corpus).",
      f"- *Framework authors.* {w_none} of {n_wi} hand-labelled WITH-AI records fit no entry; {RVN[WLA]} draws {hum_wi[WLA]} hand labels, no code (Tables 5.2, 5.3): "
      f"the list's LLM-mechanism scope places deepfake fraud. Caveat: one coder, a quota sample.",
      f"- *Database maintainers.* {RVN[mcp]} and {RVN[WLA]} need a code; the {ename('LLM07')} → {tname(SUS_T)} link yields {dropped['ON-AI'] + dropped['WITH-AI']:,} unsound labels "
      f"(Tables 5.1, 5.2, 5.A1). Caveat: labels are rules, nothing is coded yet.", "",
      "**Not supported:** prevalence; a corrected Top 10; attack chains; mitigation adoption or efficacy; trends; attribution or exploitation status; technique-level statements about how attackers operated."]

# ---------------------------------------------------------------- Limitations of the data (Table 5.7)
frame = {x: collections.Counter(S[i]["population"] for i in S if S[i]["source_class"] == x and S[i]["population"] in ("ON-AI", "WITH-AI", "BOTH")) for x in CHANNELS}
med = lambda rows: median([len(r.get("description") or "") for r in rows])
ADV = re.compile(r"attacker|threat actor|hacker|adversar|campaign|exploited|abused|scam|fraud|extort|stole|breach|malicious|\bAPT\b|state-sponsored|cybercrim|ransomware|phish|impersonat|weaponi[sz]", re.I)
wv = [C[i] for i in S if S[i]["rule"] == "with-vector"]; wv_silent = sum(not ADV.search(text(r)) for r in wv)
g_unres = len(gold_ids & set(JR["unresolved"]))
g_land = sum(len([i for i in v["snapshot_ids"] if i in gold_ids]) for v in J.values()); blind_eq = blind_agreement(rv)[0]
tier_g = collections.Counter("disagree" if PRE[i]["triage_tier"] == "disagree" else ("oos" if PRE[i]["consensus"] == "out-of-scope" else "entry") for i in gold_ids if i in PRE)
multi = [v for v in J.values() if len(v["gold_all"]) > 1]; multi_dis = sum(len({tuple(g) for g in v["gold_all"]}) > 1 for v in multi)
cover = {p: (sum(1 for i in S if S[i]["population"] == p and i in J), len(P[p])) for p in POPS}
wide = sum(x["lambda_ci"][1] - x["lambda_ci"][0] >= WIDE for x in rv["ranks"].values())
diff_codes = sum(C2RV[c] != c for c in NM["corpus"])
y19 = [r for r in R if r["year"] >= 2019]
hmax = max(str(r["date"]) for r in R if source_class(r) == "harm-db"); cmax = max(str(r["date"]) for r in cve_all)
prec = {p: collections.Counter(len(str(r["date"])) for r in P[p]) for p in POPS}
stub = [r for r in P["WITH-AI"] if r.get("description_provenance") == "original"]
cwe_pi = sum("CWE-1427" in (r.get("cwe_ids") or []) for r in R)
pi_cve = [r for r in ON if r.get("attack_vector") == "prompt-injection" and r.get("cve_ids")]
n_tech = len(A["techniques"]); n_mit_t = sum(bool(mits(t)) for t in A["techniques"])
un_on = sum(v for t, v in CNT["ON-AI"].items() if not mits(t)); un_att = sum(v for t, v in CNT["ON-AI"].items() if not mits(t) and attack_ref(t))
mit_f = {p: sum(bool(r.get("mitigations")) for r in P[p]) for p in POPS}
sc_rv = C2RV["LLM04"]
unst = ({d: sum(METH[i].get(d) == "unstated" for i in S if i in METH and S[i]["population"] == pp) for pp, dims in (("ON-AI", ("entry_point", "target")), ("WITH-AI", ("ai_role", "objective"))) for d in dims} if METH else None)
STEP = [  # this step's own tables
    ("**Labels are rule outputs.** Tables 5.1, 5.2 and 5.5 rank keyword rules, not observed techniques.",
     f"{pc(*seed_share(R))}% of OWASP codes equal the attack-vector seed; {pc(*rep(R))}% of ATLAS labels reproduce from the lookup (ON-AI {pc(*rep(ON))}%).", "5.1, 5.2, 5.5, 5.A1"),
    (f"**{ename('LLM04')} marks the CVE channel.** Its ON-AI corpus rank {crank_on['LLM04']} arrives with the feed, whatever the attack vector.",
     f"{sc_cve:,} of {len(cve_all):,} CVE/GHSA records ({pc(sc_cve, len(cve_all))}%) carry the code; within ON-AI {pc(sum('LLM04' in llm(r) for r in on_ch['cve/ghsa']), len(on_ch['cve/ghsa']))}% of cve/ghsa vs "
     f"{pc(sum('LLM04' in llm(r) for r in on_ch['harm-db']), len(on_ch['harm-db']))}% of harm-db.", "1.10, 5.1"),
    ("**Hand labels: one coder, a quota sample.** Never a ranking or a prevalence.",
     f"{len(gold_ids):,} rows: up to {cap['3-of-3']} + {cap['2-of-3']} per consensus entry ({tier_g['entry']}), all {tier_g['disagree']} disagree rows, {tier_g['oos']} no-entry-majority rows; blind = final on {pc(blind_eq, len(gold_ids))}%.", "1.14, 5.1, 5.2"),
    (f"**No-entry shares describe the sample.** The {pc(w_none, n_wi, 0)}% is not the share of WITH-AI records that fit no entry.",
     f"{none_t['disagree'][0]} of {w_none} no-entry rows are disagree rows, a tier taken in full ({taken_t['disagree'][0]} of {taken_t['disagree'][1]}).", "5.3"),
    ("**Weak vote–data concordance.** Rank-validation's whole-snapshot finding, used here only to set expectations.",
     f"weighted κ {KAPPA:.2f} ({sg(KCI[0])} to {sg(KCI[1])}) over {rv['concordance']['measurable_count']} of {rv['concordance']['total_count']} entries; {wide} of {len(rv['ranks'])} data-rank intervals span {WIDE}+ places.", "1.15"),
    ("**OWASP numbering mismatch.** Every join is by name and every table prints names.",
     f"{diff_codes} of ten entries carry different codes ({ename('LLM04')} is corpus [LLM04], rank-validation {sc_rv}).", "1.0"),
    ("**ATLAS gaps are partly framework artefacts.** Table 5.6 mixes 'not imported from ATT&CK' with 'no known mitigation'; no field records the victim's controls.",
     f"ATLAS {PINS['atlas_release']} mitigates {n_mit_t} of {n_tech} techniques; {pc(un_on, lab['ON-AI'])}% of ON-AI technique labels are unmitigated, {un_att:,} of them on techniques (or parents) adapted from ATT&CK.", "5.4, 5.6"),
]
STUDY = [  # the study's shared limitations, hosted here because this file runs last
    ("**Channel confounding.** Any pooled ON/WITH comparison compares channels.",
     f"cve/ghsa {frame['cve/ghsa']['ON-AI']:,} of {sum(frame['cve/ghsa'].values()):,} frame records are ON-AI; harm-db {frame['harm-db']['WITH-AI']:,} of {sum(frame['harm-db'].values()):,} are WITH-AI.", "2.2, 1.6, 1.7, 2.10"),
    ("**The split is rule-based.** Error rates are unmeasured.",
     f"{wv_silent:,} of {len(wv):,} vector-only WITH-AI rows contain no adversary word; {sum(source_class(r) == 'cve/ghsa' for r in P['WITH-AI'])} WITH-AI rows are CVE/GHSA; "
     f"{hum_on[WLA]} ON-AI hand labels are {RVN[WLA]}, {hum_wi[sc_rv]} WITH-AI {ename('LLM04')}.", "2.5, 5.1, 5.2"),
    ("**Join losses and merged duplicates.** Hand labels cover the pre-May-2026 part of each population.",
     f"{g_unres} of {len(gold_ids):,} hand-labelled ids unresolved; {g_land:,} land on {g_rec:,} records ({multi_dis} with disagreeing copies); coverage ON-AI {pc(*cover['ON-AI'])}%, WITH-AI {pc(*cover['WITH-AI'])}%.", "1.13"),
    ("**Six limitations stated in full in steps 1, 2 and 4**, one bounding number each: record year is ingestion (no trend); date precision; short, partly stub descriptions; "
     "CVE records coded as conventional weaknesses; step 4 unstated shares; exploitation and housekeeping fields nearly empty.",
     f"{sum(r['year'] == 2026 for r in y19):,} of {len(y19):,} records from 2019 on carry 2026; ON-AI {pc(prec['ON-AI'][7], n_on)}% month-only; median description {med(R)} characters, "
     f"{len(stub)} WITH-AI stubs ({pc(len(stub), len(P['WITH-AI']))}%); CWE-1427 on {cwe_pi} records vs {len(pi_cve)} prompt-injection CVEs; "
     + (f"entry point unstated {pc(unst['entry_point'], n_on)}%, objective {pc(unst['objective'], len(P['WITH-AI']))}%; " if METH else "")
     + f"`mitigations` filled on {mit_f['ON-AI']} ON-AI records.", "1.5, 1.7, 4.4b, 4.3, 4.1b, 4.7, 4.6"),
]
LIM = STEP + STUDY
L += ["", "## Limitations of the data", "",
      f"genai_incidents is an index of other trackers in which every label is a rule's output, so this study uses it to find and stratify incidents, never to measure them; "
      f"rows 1–{len(STEP)} bound this step's tables, rows {len(STEP) + 1}–{len(LIM)} the study as a whole (this file runs last)."]
L += head("5.7", f"{len(STEP) + len(STUDY) + 5} limitations: {len(STEP)} on this step's tables, {len(STUDY) + 5} shared by every step", f"n = {len(R):,} corpus records",
          None, ["#", "limitation", "the number that bounds it", "tables"])
L += [f"| {i} | {a} | {b} | {c} |" for i, (a, b, c) in enumerate(LIM, 1)]

# ---------------------------------------------------------------- Appendix: Table 5.A1
TECHS = sorted({t for ts in XW.values() for t in ts}, key=lambda t: (-sum(t in techs(r) for r in ON), t))
n_links = sum(len(v) for v in XW.values()); n_nomit = sum(1 for c in XW for t in XW[c] if not mits(t))
L += ["", "## Appendix: how the corpus turns OWASP codes into ATLAS techniques"]
L += head("5.A1", f"{len(XW)} OWASP codes collapse onto {len(TECHS)} ATLAS techniques; {n_nomit} of {n_links} links land on a technique with no ATLAS mitigation", f"n = {n_on:,} ON-AI records",
          "The corpus's build script derives ATLAS labels from OWASP LLM and Agentic (ASI) codes with this fixed lookup, read at the pinned tag, never run.",
          ["ATLAS technique", "OWASP codes that map to it", "mitigations (n)", "ON-AI records n (%)"])
for t in TECHS:
    L.append(f"| {label(t)} | {'; '.join(code(c) + (' [1]' if c in SUSPECT else '') for c in via(t))} | {len(mits(t))} | {npc(sum(t in techs(r) for r in ON), n_on)} |")
L += ["", f"The lookup reproduces {trio(rep)} of the corpus's ATLAS technique labels (all / ON-AI / WITH-AI); the rest come from its other rules. "
      f"[1] The lookup maps {code('LLM07')} to {label(SUS_T)}: a mapping error in this study's judgement ({SUSPECT['LLM07']}; recorded, not measured), "
      f"so Tables 5.4–5.6 drop the {dropped['ON-AI']:,} ON-AI and {dropped['WITH-AI']:,} WITH-AI labels it alone produces."]
write("s05_techniques.md", L)
