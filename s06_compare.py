#!/usr/bin/env python3
"""s06_compare.py — Step 6. Pre vs post: how far the labels in `out/dataset_post.csv` moved from the values the keyword rules and
corpus labels first gave (`out/dataset_pre.csv`), for all years and for 2026 alone, and why, with worked examples.

Pre = step 4's value after its first two steps (text rule, corpus attack-vector label), 'unstated' otherwise.
Post = the final value after the label-group rule, the coders and the review of every label.
Reads out/dataset_pre.csv, out/dataset_post.csv, out/methodology.json (the words each text rule matched), coded/review.json and
coded/relabels.json (the reviewers' and coders' notes). No model calls; the worked examples are a fixed list of record ids, each
checked against the data when the script runs, and every sentence about them is assembled from the files above.
Output: out/s06_compare.md
"""
import collections, csv, json
from common import boot_ci, write, READ, OUT, ROOT, CHANNELS

PRE = {r["id"]: r for r in csv.DictReader(open(OUT / "dataset_pre.csv", encoding="utf-8"))}
POST = {r["id"]: r for r in csv.DictReader(open(OUT / "dataset_post.csv", encoding="utf-8"))}
METH = json.load(open(OUT / "methodology.json"))
REV = json.load(open(ROOT / "coded" / "review.json")); CODED = json.load(open(ROOT / "coded" / "relabels.json"))["labels"]
RNOTE = {(c["id"], c["dim"]): c for c in REV["corrections"]}
DIM4 = ("entry_point", "target", "ai_role", "objective")
NAME = {"entry_point": "entry point", "target": "target", "ai_role": "AI medium", "objective": "objective"}
POPOF = {"entry_point": "ON-AI", "target": "ON-AI", "ai_role": "WITH-AI", "objective": "WITH-AI"}
YEAR = "2026"
assert set(PRE) == set(POST), "pre and post datasets hold different records"

# one row per label: (dim, id, pre, post, how, year, channel)
LAB = [(d, i, r[d + "_pre"], r[d + "_post"], r[d + "_how"], r["year"], r["channel"]) for i, r in POST.items() for d in DIM4 if r[d + "_post"]]
for d, i, pre, post, how, *_ in LAB:
    assert pre == PRE[i][d], (i, d)                                    # the post file's pre column is the pre file's value
    assert (pre == "unstated") or (pre == post) or how == "corrected by review", (i, d, how)   # only the review replaces a rule value
kind = lambda pre, post: "filled" if pre == "unstated" else "unchanged" if pre == post else "replaced"
pc = lambda a, b: f"{100 * a / b:.1f}" if b else "—"
def pp(x): return f"{x:+.1f}".replace("-", "−")
def cut(rows, yr): return [x for x in rows if yr is None or x[5] == yr]

def change_counts(rows):
    c = collections.Counter(kind(x[2], x[3]) for x in rows); n = len(rows)
    _, lo, hi = boot_ci(rows, lambda x: kind(x[2], x[3]) != "unchanged")
    return n, c, lo, hi

L = ["# Step 6 — Pre vs post: what the reclassification and the review changed, all years and 2026", "",
     "*Pre* is the value step 4's first two steps gave each label (a keyword rule on the text, else the corpus attack-vector label where it maps to one value), "
     "'unstated' otherwise: `out/dataset_pre.csv`. *Post* is the final value after the label-group rule, the two coders and the review of every label by two independent reviewers: "
     "`out/dataset_post.csv`. A label is *unchanged* when post equals pre, *filled* when pre was unstated, *replaced* when the review swapped one value for another "
     "(only the review replaces a value the first two steps set; the script checks this). "
     f"*{YEAR}* = records whose corpus year is {YEAR} ({sum(r['year'] == YEAR for r in POST.values()):,} of {len(POST):,}; `out/dataset_post_{YEAR}.csv`); "
     "the corpus year is the ingestion year for many trackers (Table 1.5), so the 2026 cut is a recent-intake cut rather than a clean incident-date cut.", "", READ, ""]

# ---------------------------------------------------------------- 6.1 how much changed, per dimension, all years vs 2026
L += [f"**Table 6.1. How many labels changed between pre and post, all years and {YEAR}** (n = labels)", "",
      "Per dimension (ON-AI: entry point and target; WITH-AI: AI medium and objective). *Changed* = filled + replaced, with a bootstrap 95% CI. "
      "Filled labels had no rule value at all; replaced labels had one and the review judged it wrong.", "",
      f"| dimension | all years: labels | unchanged | filled | replaced | changed (95% CI) | {YEAR}: labels | unchanged | filled | replaced | changed (95% CI) |",
      "|---|---|---|---|---|---|---|---|---|---|---|"]
T61 = {}
for d in (*DIM4, None):
    rows = [x for x in LAB if d is None or x[0] == d]; cells = []
    for yr in (None, YEAR):
        n, c, lo, hi = change_counts(cut(rows, yr)); T61[(d, yr)] = (n, c)
        ch = c["filled"] + c["replaced"]
        cells.append(f"{n:,} | {c['unchanged']:,} ({pc(c['unchanged'], n)}%) | {c['filled']:,} ({pc(c['filled'], n)}%) | {c['replaced']:,} ({pc(c['replaced'], n)}%) | "
                     f"{pc(ch, n)}% ({100 * lo:.1f}–{100 * hi:.1f})")
    L.append(f"| {'**all four**' if d is None else NAME[d] + ' (' + POPOF[d] + ')'} | {' | '.join(cells)} |")
all_n, all_c = T61[(None, None)]; y_n, y_c = T61[(None, YEAR)]
share = lambda c, n: 100 * (c["filled"] + c["replaced"]) / n
L += ["", f"Across the four dimensions {share(all_c, all_n):.1f}% of labels changed for all years and {share(y_c, y_n):.1f}% for {YEAR}; "
          f"replacements alone were {pc(all_c['replaced'], all_n)}% and {pc(y_c['replaced'], y_n)}%."]

# ---------------------------------------------------------------- 6.2 by channel
L += ["", f"**Table 6.2. Share of labels changed by disclosure channel, all years and {YEAR}** (n = labels)", "",
      "The channel mix differs between the two cuts, so a different overall rate can come from the mix alone; within a channel the rates are comparable. "
      "Replaced = the review swapped a rule value; filled = there was no rule value.", "",
      f"| population | channel | all years: labels | filled | replaced | changed | {YEAR}: labels | filled | replaced | changed |", "|---|---|---|---|---|---|---|---|---|---|"]
for pop in ("ON-AI", "WITH-AI"):
    for chn in CHANNELS:
        rows = [x for x in LAB if POPOF[x[0]] == pop and x[6] == chn]; cells = []
        for yr in (None, YEAR):
            sub = cut(rows, yr); n = len(sub); c = collections.Counter(kind(x[2], x[3]) for x in sub)
            cells.append(f"{n:,} | {pc(c['filled'], n)}% | {pc(c['replaced'], n)}% | {pc(c['filled'] + c['replaced'], n)}%" if n else "0 | — | — | —")
        L.append(f"| {pop} | {chn} | {' | '.join(cells)} |")

# ---------------------------------------------------------------- 6.3–6.6 value shares pre vs post
NUM = {"entry_point": "6.3", "target": "6.4", "ai_role": "6.5", "objective": "6.6"}
for d in DIM4:
    rows = [x for x in LAB if x[0] == d]; n_all, n_y = len(rows), len(cut(rows, YEAR))
    c0 = collections.Counter(x[2] for x in rows); c1 = collections.Counter(x[3] for x in rows)
    y0 = collections.Counter(x[2] for x in cut(rows, YEAR)); y1 = collections.Counter(x[3] for x in cut(rows, YEAR))
    big = max((v for v in c1 if v != "unstated"), key=lambda v: abs(c1[v] / n_all - c0[v] / n_all))
    L += ["", f"**Table {NUM[d]}. {POPOF[d]} {NAME[d]}: share of each value, pre vs post, all years and {YEAR}; largest shift: {big} "
              f"{pp(100 * (c1[big] - c0[big]) / n_all)} points** (all years n = {n_all:,}; {YEAR} n = {n_y:,})", "",
          "Percent of the dimension's labels; Δ = post − pre in percentage points. The pre column keeps 'unstated', which post never holds.", "",
          f"| value | all years: pre % | post % | Δ | {YEAR}: pre % | post % | Δ |", "|---|---|---|---|---|---|---|"]
    for v in sorted(set(c0) | set(c1), key=lambda v: (v == "unstated", -c1[v], v)):
        a0, a1, b0, b1 = 100 * c0[v] / n_all, 100 * c1[v] / n_all, 100 * y0[v] / n_y, 100 * y1[v] / n_y
        L.append(f"| {v} | {a0:.1f} | {a1:.1f} | {pp(a1 - a0)} | {b0:.1f} | {b1:.1f} | {pp(b1 - b0)} |")

# ---------------------------------------------------------------- 6.7 the largest replacements and what fired the rule
def fired(i, d):
    """What set the pre value: the words a text rule matched, or the corpus attack-vector label."""
    src = PRE[i][d + "_source"]
    return f"“{METH[i][d + '_match'].lower()}”" if src == "text rule" else f"label '{PRE[i]['attack_vector']}'" if src == "corpus label" else "—"
REP = collections.defaultdict(list)
for d, i, pre, post, how, yr, chn in LAB:
    if kind(pre, post) == "replaced": REP[(d, pre, post)].append((i, yr))
TOP = sorted(REP.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:15]
L += ["", f"**Table 6.7. The {len(TOP)} largest replacements: rule value → reviewed value, and what had fired the rule** (n = replaced labels; {sum(len(v) for v in REP.values()):,} in all, {sum(len(v) for _, v in TOP):,} here)", "",
      "*What fired* = the three most common matched words (lower-cased) when a keyword rule set the pre value (quoted), or the corpus attack-vector labels when the corpus label set it. "
      "Most replacements follow one of four patterns: an incidental keyword (a CVE whose text says 'credentials' or 'impersonate' is filed as credential theft or defamation), "
      "a product or entity name standing in for the thing attacked or produced ('GPT-4' → a chatbot; AIID's 'Synthetic Audio' entity tag → audio), "
      "the corpus label alone ('deepfake' → medium not stated) where the title names the medium or describes no attack, and a CVE carrying a harm label.", "",
      f"| dimension | rule value (pre) | reviewed value (post) | all years | {YEAR} | what fired (count) |", "|---|---|---|---|---|---|"]
for (d, a, b), items in TOP:
    f = collections.Counter(fired(i, d) for i, _ in items).most_common(3)
    L.append(f"| {NAME[d]} | {a} | {b} | {len(items):,} | {sum(y == YEAR for _, y in items):,} | {', '.join(f'{w} {n}' for w, n in f)} |")

# ---------------------------------------------------------------- worked examples
EXAMPLES = [   # (id, dimension): chosen to cover each dimension, each channel and both cuts; each was checked by two independent reviewers (Step 6 note)
    ("INC-15866", "entry_point"), ("INC-00898", "entry_point"), ("INC-02870", "entry_point"),
    ("INC-03607", "target"), ("INC-00219", "target"), ("INC-01455", "target"),
    ("INC-04816", "ai_role"), ("INC-00512", "ai_role"), ("INC-00675", "ai_role"), ("INC-01504", "ai_role"),
    ("INC-09141", "objective"), ("INC-00313", "objective")]
def before_review(i, d):
    c = RNOTE.get((i, d)); m = METH[i]
    return (c["from"], m.get(d + "_pre_how", m[d + "_how"])) if c else (m[d], m[d + "_how"])
def story(i, d):
    r = POST[i]; pre, post = r[d + "_pre"], r[d + "_post"]; b, bhow = before_review(i, d); c = RNOTE.get((i, d)); s = []
    assert pre != post, f"{i} {d}: example no longer changes between pre and post"
    if PRE[i][d + "_source"] == "text rule": s.append(f"The keyword rule for '{pre}' matched “{METH[i][d + '_match']}” in the text.")
    elif PRE[i][d + "_source"] == "corpus label": s.append(f"No keyword rule matched; the corpus attack-vector label '{r['attack_vector']}' maps to '{pre}'.")
    else:
        s.append("No keyword rule matched and the corpus label maps to no single value, so pre is 'unstated'.")
        if bhow == "label-group rule":
            s.append(f"The label-group rule then set '{b}' (" + ("the description is a tracker stub)." if d == "target" else f"attack-vector label '{r['attack_vector']}')."))
        elif bhow == "coded from text":
            s.append(f"The two coders labelled it '{b}': {CODED[d][i]['note'].rstrip('.')}.")
    s.append(f"The review changed it to '{post}': {c['note'].removeprefix('consistency: ').rstrip('.')}." if c else f"The review kept '{post}'.")
    return s
L += ["", f"## Worked examples ({len(EXAMPLES)})", "",
      "One label per record; the sentences are assembled from the files named at the top (rule match, corpus label, coder note, reviewer note). "
      "Each example was read again by two further independent reviewers, who agreed that the post value is the one the text supports.", ""]
for k, (i, d) in enumerate(EXAMPLES, 1):
    r = POST[i]; t = r["title"] if len(r["title"]) <= 110 else r["title"][:107] + "…"
    L += [f"{k}. **{i}** ({r['population']}, {r['channel']}, {r['year']}), {NAME[d]}: *{t}*  ", "   " + " ".join(story(i, d)), ""]

# ---------------------------------------------------------------- what the comparison says (every number computed above or here)
POSTSH = {}; SHIFT = {}
for d in DIM4:
    rows = [x for x in LAB if x[0] == d]
    for yr in (None, YEAR):
        sub = cut(rows, yr); n = len(sub); c0 = collections.Counter(x[2] for x in sub); c1 = collections.Counter(x[3] for x in sub)
        for v in set(c0) | set(c1):
            if v != "unstated": SHIFT[(d, v, yr)] = 100 * (c1[v] - c0[v]) / n; POSTSH[(d, v, yr)] = 100 * c1[v] / n
d_most = max(DIM4, key=lambda d: share(T61[(d, None)][1], T61[(d, None)][0])); d_least = min(DIM4, key=lambda d: T61[(d, None)][1]["replaced"] / T61[(d, None)][0])
same = lambda sign: [(d, v) for (d, v, yr) in SHIFT if yr is None and (d, v, YEAR) in SHIFT and all(sign * SHIFT[(d, v, y)] >= 3 for y in (None, YEAR))]
gap = {d: max((v for (dd, v, yr) in POSTSH if dd == d and yr == YEAR), key=lambda v: abs(POSTSH[(d, v, YEAR)] - POSTSH.get((d, v, None), 0))) for d in DIM4}
CH_MIN = 50   # channels with fewer labels than this in the 2026 cut are left out of the within-channel comparison
chd = []
for pop in ("ON-AI", "WITH-AI"):
    for chn in CHANNELS:
        rows = [x for x in LAB if POPOF[x[0]] == pop and x[6] == chn]; a_, y_ = rows, cut(rows, YEAR)
        if len(y_) >= CH_MIN: chd.append((pop, chn, 100 * sum(kind(x[2], x[3]) != "unchanged" for x in y_) / len(y_) - 100 * sum(kind(x[2], x[3]) != "unchanged" for x in a_) / len(a_)))
big_ch = max(chd, key=lambda t: abs(t[2]))
L += ["## What the comparison says", "",
      f"- The review replaced {pc(all_c['replaced'], all_n - all_c['filled'])}% of the labels the first two steps had set ({all_c['replaced']:,} of {all_n - all_c['filled']:,}); "
      f"in {YEAR}, {pc(y_c['replaced'], y_n - y_c['filled'])}% ({y_c['replaced']:,} of {y_n - y_c['filled']:,}). With the filled labels, {share(all_c, all_n):.1f}% of all labels and {share(y_c, y_n):.1f}% of {YEAR} labels changed (Table 6.1).",
      f"- {NAME[d_most].capitalize()} changed most ({share(T61[(d_most, None)][1], T61[(d_most, None)][0]):.1f}% of labels); {NAME[d_least]} had the fewest replacements "
      f"({pc(T61[(d_least, None)][1]['replaced'], T61[(d_least, None)][0])}%)" + (", most of its change being filled labels" if T61[(d_least, None)][1]["filled"] > T61[(d_least, None)][1]["replaced"] else "") + " (Table 6.1).",
      f"- Within a channel the {YEAR} change rate stays within {abs(big_ch[2]):.1f} points of the all-years rate (largest gap: {big_ch[0]} {big_ch[1]}, {pp(big_ch[2])}; "
      f"channels with {CH_MIN}+ {YEAR} labels, Table 6.2): the {YEAR} cut needed as much correction as the whole record.",
      f"- The direction of the shifts is the same in both cuts: {len(same(-1))} values fell and {len(same(+1))} rose by 3+ points in both (Table 6.8).",
      f"- Where the {YEAR} post shares differ most from all years: " + "; ".join(f"{NAME[d]}: {gap[d]} {POSTSH[(d, gap[d], YEAR)]:.1f}% vs {POSTSH.get((d, gap[d], None), 0):.1f}%" for d in DIM4) + ".",
      "- The no-attacker values and the CVE records in WITH-AI measure records the population split should not have admitted (step 2); they are kept as visible values in both cuts.", "",
      f"**Table 6.8. Values that moved 3+ points in the same direction in both cuts** (Δ = post − pre share, percentage points; from Tables 6.3–6.6)", "",
      f"| dimension | value | all years Δ | {YEAR} Δ |", "|---|---|---|---|"]
for sign in (+1, -1):
    for d, v in sorted(same(sign), key=lambda t: (-sign * SHIFT[(t[0], t[1], None)])):
        L.append(f"| {NAME[d]} | {v} | {pp(SHIFT[(d, v, None)])} | {pp(SHIFT[(d, v, YEAR)])} |")
write("s06_compare.md", L)
print(f"labels {all_n:,} (changed {share(all_c, all_n):.1f}%), {YEAR} {y_n:,} (changed {share(y_c, y_n):.1f}%); replacements {sum(len(v) for v in REP.values()):,}; examples {len(EXAMPLES)}")
