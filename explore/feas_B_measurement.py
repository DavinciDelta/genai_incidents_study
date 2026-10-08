"""feas_B_measurement.py — Claim B: do measurement choices change the conclusions?

Headlines: CVE/GHSA ON-AI share of the channel's frame units, harm-db WITH-AI share, research ON-AI share, pooled ON/(ON+WITH),
ON:WITH ratio, Cramér's V on channel x {ON, WITH}.
B1 unit (deduplication): merged records (published) vs pre-merge source ids (record's channel / each id's own tracker channel)
   vs templated title series collapsed; plus how much residual duplication a title-similarity check finds
B2 human correction: step 2 vs step 4 reviewed (no-attacker / misplaced-CVE out; + the 'other/other' ON-AI leak moved to WITH-AI)
   vs the rank-validation human's 'no entry fits' removed (hand-labelled frame records only)
B3 record type: all vs no demonstrations (research, research-demonstrated, red-team) vs realized (real-world + disclosure) vs observed (real-world)
B4 channel weights for the pooled share: record weights, equal channel weights, channel's share of the whole corpus, the attainable range;
   pooled share by year, as published and with the channel mix held at the all-years mix
B5 every combination of unit x coding x record type (64 cells) x weights: the range of each headline
Writes feas_B_measurement.json next to this file.
"""
import collections, itertools, re
from feas_lib import (CH, FRAME, DEMO, load_all, load_rv, join_rv, classify, reviewed_pop, tracker_channel, metrics, line, HEAD, dump, fmt_n)

C, S, P = load_all()
T = {i: classify(C[i], use_vector=False)[0] for i in C}
out = {}
pct = lambda a, b: f"{100*a/b:.1f}%" if b else "—"

# ------------------------------------------------------------------ codings, units, record-type cuts
CODING = {
    "published (step 2)": lambda i: S[i]["population"],
    "text only (vector blanked)": lambda i: T[i],
    "reviewed (step 4)": lambda i: reviewed_pop(i, S, P),
    "reviewed + leak to WITH": lambda i: reviewed_pop(i, S, P, leak_to_with=True),
}
def tmpl(t):
    t = t.lower(); t = re.sub(r"[\"“”‘’'][^\"“”‘’']{1,80}[\"“”‘’']", "Q", t)
    t = re.sub(r"\(?(cve|ghsa)-[\w-]+\)?", "ID", t); t = re.sub(r"\d[\w.]*", "#", t)
    return re.sub(r"\s+", " ", t).strip()
# series groups are formed over the records that are in the frame under ANY coding, so the grouping is fixed across codings
ANYF = [i for i in C if any(f(i) in FRAME for f in CODING.values())]
grp = collections.defaultdict(list)
for i in ANYF: grp[tmpl(C[i]["title"])].append(i)
series_w = {i: (1 / len(v) if len(v) >= 3 else 1) for v in grp.values() for i in v}
UNITS = {
    "merged record (published)": lambda i: [(S[i]["source_class"], 1)],
    "source id, record's channel": lambda i: [(S[i]["source_class"], len(C[i].get("source_ids") or [1]))],
    "source id, own tracker's channel": lambda i: [(tracker_channel(s), 1) for s in (C[i].get("source_ids") or [])] or [(S[i]["source_class"], 1)],
    "templated series collapsed": lambda i: [(S[i]["source_class"], series_w.get(i, 1))],
}
RTYPE = {
    "all record types": lambda r: True,
    "no demonstrations": lambda r: r["category"] not in DEMO,
    "realized (real-world + disclosure)": lambda r: r["category"] in ("real-world", "vulnerability-disclosure"),
    "observed (real-world only)": lambda r: r["category"] == "real-world",
}
def units(coding="published (step 2)", unit="merged record (published)", rtype="all record types"):
    pop, un, keep = CODING[coding], UNITS[unit], RTYPE[rtype]
    for i, r in C.items():
        if not keep(r): continue
        p = pop(i)
        for ch, w in un(i): yield ch, p, w
BASE = metrics(units())

def table(title, rows):
    print(f"\n## {title}\n"); print("\n".join(HEAD)); print(line("baseline: published, merged records, all types", BASE))
    for lab, m in rows: print(line(lab, m))
    out[title] = {lab: m for lab, m in [("baseline", BASE)] + rows}

# ------------------------------------------------------------------ B1 units
print("# B1. Unit of count (deduplication)")
F0 = [i for i in C if S[i]["population"] in FRAME]
print(f"\nFrame records {len(F0):,} carry {sum(len(C[i]['source_ids']) for i in F0):,} source ids; {sum(len(C[i]['source_ids']) > 1 for i in F0)} records merge 2+ ids; "
      "largest: " + ", ".join(f"{i} {len(C[i]['source_ids'])} ids ({S[i]['source_class']}, {S[i]['population']})" for i in sorted(F0, key=lambda i: -len(C[i]['source_ids']))[:4]) + ".")
cv, sid = collections.Counter(), collections.Counter()
for r in C.values():
    cv.update(set(r.get("cve_ids") or [])); sid.update(set(r.get("source_ids") or []))
print(f"Residual duplicate keys after the corpus merge: CVE ids on 2+ records {sum(v > 1 for v in cv.values())} of {len(cv):,}; source ids on 2+ records {sum(v > 1 for v in sid.values())} of {len(sid):,}.")
big = sorted([v for v in grp.values() if len(v) >= 3], key=len, reverse=True)
print(f"Templated title series (3+ frame records sharing a title once quoted phrases, CVE/GHSA ids and numbers are removed): {len(big)} series, "
      f"{sum(map(len, big))} records; largest: " + "; ".join(f"{len(v)} x '{C[v[0]]['title'][:60]}' ({S[v[0]]['source_class']}, {collections.Counter(S[i]['population'] for i in v).most_common(1)[0][0]})" for v in big[:3]))
STOP = set("a an the of in on for to and or by with via from at as is are was were be its it after over into using used uses use reportedly allegedly purportedly ai generated vulnerability cve ghsa before version versions contains".split())
tok = {i: {w for w in re.findall(r"[a-z0-9]+", C[i]["title"].lower()) if w not in STOP and len(w) > 2} for i in F0}
inv = collections.defaultdict(set)
for i in F0:
    for w in tok[i]: inv[w].add(i)
pairs = 0; pair_ch = collections.Counter()
for i in sorted(F0):
    cand = collections.Counter(j for w in tok[i] if len(inv[w]) <= 200 for j in inv[w] if j > i)
    for j, k in cand.items():
        if k / len(tok[i] | tok[j]) >= 0.6: pairs += 1; pair_ch[(S[i]["source_class"], S[j]["source_class"])] += 1
print(f"Title-similarity check (token Jaccard >= 0.6, stop words out): {pairs} record pairs among {len(F0):,} frame records ({dict(pair_ch)}); "
      "these are mostly templated series of distinct items, not the same event (read a sample: feas_B prints none, proto in proto_dup.py).")
table("B1. Unit of count", [(u, metrics(units(unit=u))) for u in list(UNITS)[1:]])

# ------------------------------------------------------------------ B2 human correction
print("\n# B2. Human (LLM-reviewer) correction")
rv = load_rv(); J = join_rv(C, rv)["rows"]
HF = [i for i in F0 if i in J and J[i]["gold_labels"] is not None]
m_h = metrics((S[i]["source_class"], S[i]["population"], 1) for i in HF)
m_h2 = metrics((S[i]["source_class"], S[i]["population"], 1) for i in HF if J[i]["gold_labels"] != [])
table("B2. Correction", [(c, metrics(units(coding=c))) for c in list(CODING)[1:]] +
      [(f"hand-labelled frame records only ({len(HF)}), step-2 populations", m_h),
       (f"same, the human's 'no entry fits' records dropped ({sum(J[i]['gold_labels'] == [] for i in HF)})", m_h2)])
print("\n(The hand-labelled rows were drawn by quota, so the last two rows describe that sample only.)")
KEEP = FRAME + ("NONE (review)", "CVE misplaced (review)")
mk = metrics(units(coding="reviewed (step 4)"), frame=KEEP)
print("\nKeeping the records the review took out in the denominator (as their own categories, not dropped):\n")
print("\n".join(HEAD)); print(line("reviewed, removed records kept as 'no attacker (review)' / 'CVE misplaced (review)'", mk))
for ch in CH:
    t = mk["table"][ch]; n = mk["frame_n"][ch]
    print(f"- {ch}: " + ", ".join(f"{p} {fmt_n(t.get(p, 0))} ({100*t.get(p, 0)/n:.1f}%)" for p in KEEP) + f" of {fmt_n(n)}")
out["B2_keep"] = mk

# ------------------------------------------------------------------ B3 record type
print("\n# B3. Demonstrations vs observed attacks")
rt = collections.Counter((S[i]["source_class"], C[i]["category"]) for i in F0)
print("\nFrame records by channel and record type: " + "; ".join(f"{ch}: " + ", ".join(f"{k[1]} {v}" for k, v in sorted(rt.items(), key=lambda kv: -kv[1]) if k[0] == ch) for ch in CH))
print(f"exploited_in_wild set: {sum(C[i].get('exploited_in_wild') is True for i in F0)} frame records, {sum(r.get('exploited_in_wild') is True for r in C.values())} corpus-wide.")
table("B3. Record type", [(t, metrics(units(rtype=t))) for t in list(RTYPE)[1:]])

# ------------------------------------------------------------------ B4 channel weights
print("\n# B4. Channel weights for the pooled ON share")
def pooled(m, w):
    """pooled ON/(ON+WITH) with channel ch carrying weight w[ch] (normalised over channels that have ON+WITH units)."""
    t = m["table"]; chs = [ch for ch in CH if t[ch].get("ON-AI", 0) + t[ch].get("WITH-AI", 0) > 0]
    s = sum(w[ch] for ch in chs)
    return sum(w[ch] / s * t[ch].get("ON-AI", 0) / (t[ch].get("ON-AI", 0) + t[ch].get("WITH-AI", 0)) for ch in chs)
def wsets(m):
    t = m["table"]; allrec = collections.Counter(S[i]["source_class"] for i in C)
    return {"record weights (as published)": {ch: t[ch].get("ON-AI", 0) + t[ch].get("WITH-AI", 0) for ch in CH},
            "equal channel weights (1/3 each)": {ch: 1 for ch in CH},
            "CVE/GHSA and harm-db equal, research 0": {"cve/ghsa": 1, "harm-db": 1, "research/other": 0},
            "channel's share of all 15,666 records": dict(allrec)}
print("\n| weighting | pooled ON / (ON+WITH) | ON:WITH |\n|---|---|---|")
for k, w in wsets(BASE).items():
    p = pooled(BASE, w); print(f"| {k} | {100*p:.1f}% | {p/(1-p):.2f} |")
sh = {ch: BASE["table"][ch]["ON-AI"] / (BASE["table"][ch]["ON-AI"] + BASE["table"][ch]["WITH-AI"]) for ch in CH}
print(f"| attainable range (any channel weights) | {100*min(sh.values()):.1f}% – {100*max(sh.values()):.1f}% | {min(sh.values())/(1-min(sh.values())):.2f} – {max(sh.values())/(1-max(sh.values())):.2f} |")
out["B4"] = {k: pooled(BASE, w) for k, w in wsets(BASE).items()} | {"range": [min(sh.values()), max(sh.values())]}

print("\n**Pooled ON share by record year: as published, and with the channel mix held at the all-years mix**\n")
mixw = {ch: BASE["table"][ch]["ON-AI"] + BASE["table"][ch]["WITH-AI"] for ch in CH}
print("| year | ON+WITH | channel mix (cve/ghsa, harm-db, research) | pooled ON share | ON share at all-years mix | within-channel ON share (cve, harm-db, research) |\n|---|---|---|---|---|---|")
yr = {}
for y in (2020, 2021, 2022, 2023, 2024, 2025, 2026):
    t = collections.defaultdict(collections.Counter)
    for i in F0:
        if C[i]["year"] == y: t[S[i]["source_class"]][S[i]["population"]] += 1
    n = {ch: t[ch]["ON-AI"] + t[ch]["WITH-AI"] for ch in CH}; N = sum(n.values())
    on = sum(t[ch]["ON-AI"] for ch in CH)
    within = {ch: (t[ch]["ON-AI"] / n[ch] if n[ch] else None) for ch in CH}
    if all(v is not None for v in within.values()):
        std = sum(mixw[ch] * within[ch] for ch in CH) / sum(mixw.values()); std_s = f"{100*std:.1f}%"
    else:
        std = None; std_s = "— (a channel has no records)"
    yr[y] = {"N": N, "pooled": on / N, "std": std, "within": within, "mix": n}
    print(f"| {y} | {N:,} | {', '.join(pct(n[ch], N) for ch in CH)} | {pct(on, N)} | {std_s} | "
          + ", ".join(f"{100*within[ch]:.1f}% ({t[ch]['ON-AI']}/{n[ch]})" if within[ch] is not None else "—" for ch in CH) + " |")
out["B4_year"] = yr

# ------------------------------------------------------------------ B5 full grid
print("\n# B5. Every combination (4 codings x 4 units x 4 record-type cuts = 64 cells; pooled share also x 3 weightings)\n")
cells = []
for c, u, t in itertools.product(CODING, UNITS, RTYPE):
    m = metrics(units(c, u, t))
    ws = wsets(m)
    cells.append({"coding": c, "unit": u, "rtype": t, "cve_on": m["cve_on"], "hdb_with": m["hdb_with"], "res_on": m["res_on"], "V": m["V"],
                  "pooled": {k: pooled(m, w) for k, w in list(ws.items())[:3]}, "frame_n": m["frame_n"]})
def rng(key, sub=None):
    vals = [(c[key] if sub is None else c[key][sub], c) for c in cells]
    lo, hi = min(vals, key=lambda v: v[0]), max(vals, key=lambda v: v[0])
    return lo, hi
print("| headline | min (cell) | max (cell) |\n|---|---|---|")
for lab, key, sub in (("CVE/GHSA ON-AI share", "cve_on", None), ("harm-db WITH-AI share", "hdb_with", None), ("research ON-AI share", "res_on", None),
                      ("Cramér's V", "V", None), ("pooled ON share, record weights", "pooled", "record weights (as published)"),
                      ("pooled ON share, equal channel weights", "pooled", "equal channel weights (1/3 each)")):
    (lo, cl), (hi, ch_) = rng(key, sub)
    f = (lambda x: f"{x:.2f}") if key == "V" else (lambda x: f"{100*x:.1f}%")
    print(f"| {lab} | {f(lo)} ({cl['coding']}; {cl['unit']}; {cl['rtype']}; n cve {fmt_n(cl['frame_n']['cve/ghsa'])}, hdb {fmt_n(cl['frame_n']['harm-db'])}) | "
          f"{f(hi)} ({ch_['coding']}; {ch_['unit']}; {ch_['rtype']}; n cve {fmt_n(ch_['frame_n']['cve/ghsa'])}, hdb {fmt_n(ch_['frame_n']['harm-db'])}) |")
sign = sum(c["cve_on"] > 0.5 and c["hdb_with"] > 0.5 for c in cells)
print(f"\nCells where CVE/GHSA is majority ON-AI AND harm-db majority WITH-AI: {sign} of {len(cells)}.")
pr = [c["pooled"]["record weights (as published)"] for c in cells]
print(f"Cells where the pooled ON share (record weights) is above 50%: {sum(p > 0.5 for p in pr)} of {len(cells)} (the pooled majority flips with the choices).")
out["B5"] = cells
dump("feas_B_measurement.json", out)
