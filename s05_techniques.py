#!/usr/bin/env python3
"""s05_techniques.py — Step 5. One question: which OWASP LLM Top 10 categories stand out in each population against the OWASP
community vote. Two sources: the corpus's OWASP codes (keyword labels) and rank-validation's report of the community vote. One
person's hand labels (rank-validation's adjudicator) disagree with the corpus and are treated as a limitation, in one table. Runs
last, so it also hosts the study's Use cases and Limitations of the data. Step 4 answers HOW attacks happened; this file does not repeat it.

Everything here is a corpus keyword label or a read of another project's artifacts; nothing is coded from reports yet.
llm() is where hand codes replace the corpus labels in the next phase.
Output: out/s05_techniques.md
"""
import ast, collections, json, re
from common import load_full, load_rv, join_rv, load_prelabels, owasp_names, source_class, text, write, READ, OUT, EXT, CYCLE, CHANNELS

S = json.load(open(OUT / "split.json")); C = load_full(); R = list(C.values())
rv = load_rv(); JR = join_rv(C, rv); J = JR["rows"]; PRE = load_prelabels()
NM = owasp_names(rv); RV2C, C2RV, RVN = NM["rv2corpus"], NM["corpus2rv"], NM["rv"]
POPS = ("ON-AI", "WITH-AI"); P = {p: [C[i] for i, s in S.items() if s["population"] == p] for p in POPS}
METH = json.load(open(OUT / "methodology.json"))      # step 4's rule outputs; the WITH-AI 'No entry fits' kinds are its attacker-objective rule
DEMO = ("research", "research-demonstrated", "red-team")
MIN_RECORDS = 30     # below this many corpus records a category is marked § and left out of the titles and 'What stands out' bullets
SMALL = "§"
MARKER_SHARE = 0.9   # a code is a channel marker (‡) when it sits on this share of one channel's records, or of its own assignments
MIN_HAND = 2         # a category or proposed addition gets its own row in Table 5.3 from this many hand labels; smaller ones are pooled
MIN_HEAD = 10        # a proposed addition is named in the limitation paragraph from this many hand labels
MIN_KIND = 4         # a 'No entry fits' kind gets its own sub-row from this many records; two or more smaller kinds are pooled
TITLE = 28
WLA = next(e for e, n in RVN.items() if n == "Weaponized LLM Abuse")
TAX = CYCLE / "taxonomy"
# the three tracker-stub forms, as step 4 reads them from a description's opening words (its STUBS list; kept in step here so this file stands alone)
STUB = ("Tracked by the OECD", "AI Incident Database (AIID) entry #", "AIAAIC-tracked incident")
def stub(r): return (r.get("description") or "").startswith(STUB)

def llm(r): return r.get("owasp_llm") or []              # <- hand codes replace this after the coding phase
def ename(c): return RVN[C2RV[c]]                        # rank-validation's entry name for a corpus OWASP LLM code
def code(c): return f"{ename(c)} [{c}]"
def pc(a, b, d=1): return f"{100*a/b:.{d}f}" if b else "—"
def npc(a, b): return f"{a:,} ({pc(a, b)}%)"
def ranks(counter): return {k: 1 + sum(w > v for w in counter.values()) for k, v in counter.items() if v}    # ties share a rank
def cut(t, k=TITLE): t = (t or "").replace("|", "/"); return t if len(t) <= k else t[:k].rsplit(" ", 1)[0] + "…"   # cut at a word boundary
def signed(x): return (f"{x:+g}" if x else "0").replace("-", "−")
def andlist(xs): xs = list(xs); return ", ".join(xs[:-1]) + (" and " if len(xs) > 1 else "") + xs[-1]
def head(num, title, n, desc, cols): return ["", f"**Table {num}. {title}** ({n})", ""] + ([desc, ""] if desc else []) + ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
def rub(fname, phrase):
    """A phrase quoted from one of rank-validation's rubric files (read only): asserted to be there, so every quote traces to the file."""
    assert phrase in (TAX / fname).read_text(), f"{phrase!r} not in {fname}"; return phrase
def vote_ci():
    """Vote-rank 90% intervals from rank-validation's rank_comparison_report.md (load_rv parses the line but keeps only the point rank)."""
    pat = re.compile(r"^\|\s*([A-Z0-9-]+)\s*\|[^|]*\|\s*([\d.]+) \(([\d.]+)[–-]([\d.]+)\)")
    return {m.group(1): (float(m.group(3)), float(m.group(4))) for l in open(CYCLE / "results/rank_comparison_report.md") if (m := pat.match(l.strip()))}
def src_assign(path, name):
    """The AST of one top-level assignment in a script, read (never run) — here the corpus build script's attack_vector → OWASP seed table."""
    return next(n.value for n in ast.parse(path.read_text()).body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == name)
SEED = ast.literal_eval(src_assign(EXT / "corpus_merge_and_dedupe.py", "_VECTOR_TO_OWASP_LLM"))          # attack_vector -> OWASP LLM seed codes
def seed_share(rows):
    lab = [(r, c) for r in rows for c in llm(r)]; return sum(c in SEED.get(r.get("attack_vector") or "", []) for r, c in lab), len(lab)
def seed_vectors(c): return sorted(v for v, cs in SEED.items() if c in cs)
def objective(i):
    """Step 4's attacker-objective value for a record; tolerant of a value stored as {'value': …} by a later step 4."""
    v = (METH.get(i) or {}).get("objective", "unstated"); return v.get("value", "unstated") if isinstance(v, dict) else v
def words(s): return len(re.sub(r"[*_`]", "", s).split())
VCI = vote_ci(); VR = {e: rv["ranks"][e]["vote_rank"] for e in rv["ranks"]}

# hand-labelled rows per population: (id, record, label list in rank-validation ids; [] = no entry fits)
GOLD = {p: [(i, C[i], J[i]["gold_labels"]) for i, s in S.items() if s["population"] == p and i in J and J[i]["gold_labels"] is not None] for p in POPS}
HUM = {p: collections.Counter(e for _, _, gl in GOLD[p] for e in gl) for p in POPS}
HRANK = {p: ranks(HUM[p]) for p in POPS}                 # hand-label rank within the population's hand-labelled sample
NONE = {p: [(i, r) for i, r, gl in GOLD[p] if gl == []] for p in POPS}
def note(i): return rv["gold"][J[i]["snapshot_id"]].get("notes")
def tier_of(i): return (PRE.get(J[i]["snapshot_id"]) or {}).get("triage_tier")
KAPPA, KCI = rv["concordance"]["weighted_kappa_median"], rv["concordance"]["weighted_kappa_ci"]
def sg(x): return f"{x:.2f}".replace("-", "−")
cve_all = [r for r in R if source_class(r) == "cve/ghsa"]; sc_cve = sum("LLM04" in llm(r) for r in cve_all)
ENTRIES = sorted(rv["ranks"], key=lambda e: (VR[e], e)); TEN = [e for e in ENTRIES if e in RV2C]; ADDS = [e for e in ENTRIES if e not in RV2C]
NG = {p: len(GOLD[p]) for p in POPS}; NN = {p: len(NONE[p]) for p in POPS}
gold_ids = set(rv["gold"]); g_rec = sum(v["gold_labels"] is not None for v in J.values()); g_lost = len(gold_ids) - g_rec
g_pop = collections.Counter(S[i]["population"] for i, v in J.items() if v["gold_labels"] is not None)      # where the joined hand-labelled records fall
quota = collections.Counter((PRE[i]["consensus"], PRE[i]["agreement"]) for i in gold_ids if i in PRE and PRE[i]["triage_tier"] != "disagree" and PRE[i]["consensus"] != "out-of-scope")
q3, q2 = (max(v for (c, aa), v in quota.items() if aa == a) for a in ("3-of-3", "2-of-3"))    # the per-entry quota cells, recovered as the largest cell per agreement level
ALL_CH = {x: [r for r in R if source_class(r) == x] for x in CHANNELS}
def marker_why(c):
    """(kind, share, channel) when a code is a channel marker corpus-wide: 'on' MARKER_SHARE of one channel's records, or 'from' one channel for MARKER_SHARE of its labels."""
    tot = sum(c in llm(r) for r in R)
    for x, ch in ALL_CH.items():
        k = sum(c in llm(r) for r in ch)
        if k >= MARKER_SHARE * len(ch): return "on", pc(k, len(ch)), x
        if k >= MARKER_SHARE * tot: return "from", pc(k, tot), x
MARKER = {c: w for c in NM["corpus"] if (w := marker_why(c))}                                       # code -> (kind, share, channel)
_ons = [f"{ename(c)} on {w}% of {x}" for c, (k, w, x) in sorted(MARKER.items()) if k == "on"]
_froms = collections.defaultdict(list)
for c, (k, w, x) in sorted(MARKER.items()):
    if k == "from": _froms[x].append(f"{ename(c)} {w}%")
MARKER_DEF = (f"‡ = channel marker: corpus-wide, the code sits on {MARKER_SHARE:.0%}+ of one channel's records or {MARKER_SHARE:.0%}+ of its labels come from one channel "
              f"({'; '.join(_ons + [f'{", ".join(v)} from {x}' for x, v in _froms.items()])}); its rank arrives with the feed")
# the rubric's requirement, quoted from the taxonomy files; and this study's reading of each population's 'No entry fits' rows (a recorded judgement, not a measurement)
RUB = {"pi": rub("LLM01_PromptInjection.md", "alters the model's behavior in ways the operator did not intend"),
       "mis": rub("LLM09_Misinformation.md", "trusted and acted upon"), "wla": rub("weaponized-llm-abuse.md", "cyberattacks against third-party targets")}
SUBSTANTIVE = "No concrete LLM vulnerability mechanism in incident text."
READING = {"ON-AI": "classifier evaluations and misused decision tools", "WITH-AI": "deepfake fraud and abuse imagery"}
CNT = {p: collections.Counter(c for r in P[p] for c in set(llm(r))) for p in POPS}; CRANK = {p: ranks(CNT[p]) for p in POPS}
PLACES = {p: {e: VR[e] - CRANK[p][RV2C[e]] for e in TEN if RV2C[e] in CRANK[p]} for p in POPS}
def demo_share(p, c): rows = [r for r in P[p] if c in llm(r)]; return sum(r["category"] in DEMO for r in rows), len(rows)
diff_codes = sum(C2RV[c] != c for c in NM["corpus"])

# ---------------------------------------------------------------- opener
L = ["# Step 5 — Which attack categories stand out against the community vote", "",
     f"Generated by `s05_techniques.py` (`make s05`); do not edit by hand; inputs pinned in `external/PINS.json`. {READ}", "",
     f"Which OWASP LLM Top 10 categories does each population rank higher or lower than the community vote? Two sources: the corpus's OWASP categories (keyword labels) "
     f"and the community vote with its 90% interval as rank-validation reports ({len(ENTRIES)} candidates ranked by respondents; its data rank is Table 1.15). "
     f"One person's hand labels disagree with the corpus: a limitation below (Table 5.3)."]

# ---------------------------------------------------------------- Tables 5.1 / 5.2
def category_table(p, num):
    rows, n, on = P[p], len(P[p]), p == "ON-AI"; cnt, crank, places = CNT[p], CRANK[p], PLACES[p]
    big = [e for e in places if cnt[RV2C[e]] >= MIN_RECORDS]
    top, bot = max(places[e] for e in big), min(places[e] for e in big)
    his = [e for e in big if places[e] == top]; los = [e for e in big if places[e] == bot]; hi = his[0]
    nm = lambda es: andlist(ename(RV2C[e]) for e in es)
    cols = ["category [corpus code]", "vote rank (90% interval)", "corpus records n (%)", "corpus rank", "places above the vote"] + (["demonstrated, % of its records"] if on else [])
    if on:
        desc = (f"Rows: the ten categories in vote order; codes are the corpus's, not OWASP's (Table 1.0). *Corpus rank* orders them by {p} records carrying the code; "
                f"*places above the vote* = vote rank − corpus rank (+ = the corpus ranks it higher); {SMALL} = under {MIN_RECORDS} corpus records, outside title and "
                f"bullets; *demonstrated* = research, research-demonstrated or red-team. {MARKER_DEF}.")
    else:
        wd = sum(r["category"] in DEMO for r in rows)
        desc = (f"The OWASP list scopes LLM applications; records where the AI is the attacker's instrument fall outside it by design. Columns as in Table 5.1 "
                f"minus *demonstrated* ({p} has {wd} demonstration record{'s' * (wd != 1)}).")
    L.extend(head(num, f"{p}, categories with {MIN_RECORDS}+ records: {nm(his)} {signed(top)} places above its vote rank, {nm(los)} {signed(bot)}", f"n = {n:,} {p} records", desc, cols))
    for e in TEN:
        c = RV2C[e]; lo_, hi_ = VCI[e]; d, b = demo_share(p, c)
        L.append(f"| {code(c)}{'‡' if c in MARKER else ''} | {VR[e]:g} ({lo_:g}–{hi_:g}) | {npc(cnt[c], n)}{SMALL if cnt[c] < MIN_RECORDS else ''} | {crank.get(c, '—')} | "
                 f"{signed(places[e]) if e in places else '—'} |" + (f" {pc(d, b, 0)} |" if on else ""))
    def why(e):
        c = RV2C[e]; d, b = demo_share(p, c)
        if c in MARKER: return " (channel marker ‡)"
        av = collections.Counter(r.get("attack_vector") or "none" for r in rows if c in llm(r)).most_common(1)[0]
        return (f" ({pc(d, b, 0)}% demonstrations" if on else " (") + f"; seeded from {', '.join(seed_vectors(c))}; top vector on its records: {av[0]}, {av[1]} of {b})"
    marks = [c for c in sorted(MARKER) if cnt[c] >= MIN_RECORDS]
    ch = {x: [r for r in rows if source_class(r) == x] for x in CHANNELS}
    def mark_line(c):
        sh = {x: (sum(c in llm(r) for r in ch[x]), len(ch[x])) for x in CHANNELS if ch[x]}; mx = MARKER[c][2]
        ox = max((x for x in sh if x != mx), key=lambda x: sh[x][0] / sh[x][1])
        return f"{ename(c)} (rank {crank[c]}): {pc(*sh[mx])}% of {mx} vs {pc(*sh[ox])}% of {ox}"
    L.extend(["", "What stands out:", "",
              f"- Largest move up: {nm(his)} {signed(top)}{why(hi)}" + (" (tied)" if len(his) > 1 else "") + ".",
              f"- Largest move down: {nm(los)} {signed(bot)}{why(los[0]) if len(los) == 1 else ''}" + (" (tied)" if len(los) > 1 else "") + ".",
              f"- Channel markers ‡ (share of {p} records per channel, marker vs next): {'; '.join(mark_line(c) for c in marks)}." if marks else f"- No channel marker ‡ has {MIN_RECORDS}+ records in this population."])
category_table("ON-AI", "5.1"); category_table("WITH-AI", "5.2")
L += ["", f"*Corpus rank* orders keyword labels, not incidents, and the vote is {len(ENTRIES)} candidates ranked by respondents; neither table is a corrected Top 10."]

# ---------------------------------------------------------------- 2026 records only: is the recent record closer to the vote?
def spearman(xs, ys):
    """Spearman rank correlation of two equal-length lists of ranks (ties already shared); None below 3 pairs."""
    n = len(xs)
    if n < 3: return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys)); sxx = sum((x - mx) ** 2 for x in xs); syy = sum((y - my) ** 2 for y in ys)
    return sxy / (sxx * syy) ** 0.5 if sxx and syy else None
YEAR = 2026
P26 = {p: [r for r in P[p] if r["year"] == YEAR] for p in POPS}
CNT26 = {p: collections.Counter(c for r in P26[p] for c in set(llm(r))) for p in POPS}; CRANK26 = {p: ranks(CNT26[p]) for p in POPS}
def rho(p, cnt, crank):
    es = [e for e in TEN if RV2C[e] in crank and cnt[RV2C[e]] >= MIN_RECORDS]
    return spearman([VR[e] for e in es], [crank[RV2C[e]] for e in es]), len(es)
RHO = {p: (rho(p, CNT[p], CRANK[p]), rho(p, CNT26[p], CRANK26[p])) for p in POPS}
fr = lambda v: "—" if v is None else f"{v:+.2f}".replace("-", "−")
L += head("5.4", f"{YEAR} records only: corpus rank against the vote ({', '.join(f'{p} ρ {fr(RHO[p][1][0])} vs {fr(RHO[p][0][0])} all years' for p in POPS)})",
          "; ".join(f"{p} n = {len(P26[p]):,} of {len(P[p]):,}" for p in POPS),
          f"Records dated {YEAR} only (record year reflects when a tracker was ingested, Table 1.5, and CVE dates are month-only). ρ is Spearman's rank correlation between "
          f"the vote rank and the corpus rank over the categories with {MIN_RECORDS}+ records in that cut (+1 = same order, −1 = reversed; no CI, ten categories at most), "
          f"shown beside the all-years value; a rise would mean the recent record sits closer to the vote. Columns per population: corpus records in {YEAR}, corpus rank in "
          f"{YEAR}, places above the vote in {YEAR}, and the all-years rank for comparison.",
          ["category [corpus code]", "vote rank"] + [f"{p}: {x}" for p in POPS for x in (f"{YEAR} records n (%)", f"{YEAR} rank", f"{YEAR} places above the vote", "all-years rank")])
for e in TEN:
    c = RV2C[e]; cells = []
    for p in POPS:
        n26, cnt, crank = len(P26[p]), CNT26[p], CRANK26[p]
        pl = (VR[e] - crank[c]) if c in crank else None
        cells += [f"{npc(cnt[c], n26)}{SMALL if cnt[c] < MIN_RECORDS else ''}", str(crank.get(c, "—")), signed(pl) if pl is not None else "—", str(CRANK[p].get(c, "—"))]
    L.append(f"| {code(c)}{'‡' if c in MARKER else ''} | {VR[e]:g} | " + " | ".join(cells) + " |")
moved = {p: [(e, CRANK26[p][RV2C[e]] - CRANK[p][RV2C[e]]) for e in TEN if RV2C[e] in CRANK26[p] and RV2C[e] in CRANK[p] and CRANK26[p][RV2C[e]] != CRANK[p][RV2C[e]]] for p in POPS}
L += ["", "What changes in the " + f"{YEAR} cut: " + "; ".join(
    f"{p}: ρ {fr(RHO[p][0][0])} → {fr(RHO[p][1][0])} over {RHO[p][1][1]} categories" + (", ranks that move: " + ", ".join(f"{ename(RV2C[e])} {signed(-d)}" for e, d in moved[p]) if moved[p] else ", no category changes rank") for p in POPS) + ". "
    f"The {YEAR} rows are {pc(len(P26['ON-AI']), len(P['ON-AI']), 0)}% of ON-AI and {pc(len(P26['WITH-AI']), len(P['WITH-AI']), 0)}% of WITH-AI, "
    f"and the vote was collected before most of them were disclosed, so a closer match would say the vote anticipated the feed, not that the feed confirms the vote. "
    f"`out/dataset_post_2026.csv` holds these rows."]

# ---------------------------------------------------------------- Limitation: the hand labels (Table 5.3)
TIERS = (("disagree", "disagreement rows"), ("split", "where two pre-labellers agreed"), ("agree", "where three did"))
GW = GOLD["WITH-AI"]
none_t = {t: (sum(gl == [] for i, _, gl in GW if tier_of(i) == t), sum(tier_of(i) == t for i, _, _ in GW)) for t, _ in TIERS}
top_hand = max(TEN, key=lambda e: (HUM["ON-AI"][e], -VR[e]))
heads = {p: sorted((e for e in ADDS if HUM[p][e] >= MIN_HEAD), key=lambda e: -HUM[p][e]) for p in POPS}
def ord_(k): return f"{k}{'th' if 10 <= k % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(k % 10, 'th')}"
LIM = (f"Rank-validation's adjudicator hand-labelled {NG['ON-AI']} ON-AI and {NG['WITH-AI']} WITH-AI records, drawn by quota (every pre-labeller disagreement, then "
       f"{q3} unanimous + {q2} majority rows per entry), so counts are not prevalence. {RVN[top_hand]}, the top ON-AI hand label ({HUM['ON-AI'][top_hand]}), is "
       f"the corpus's {ord_(CRANK['ON-AI'][RV2C[top_hand]])}; {andlist(f'{RVN[e]} ({HUM[p][e]})' for p in POPS for e in heads[p])} have no corpus code; no entry fits "
       f"{NN['ON-AI']} ON-AI ({pc(NN['ON-AI'], NG['ON-AI'])}%) and {NN['WITH-AI']} WITH-AI ({pc(NN['WITH-AI'], NG['WITH-AI'])}%) rows, {none_t['disagree'][0]} of them "
       f"disagreement rows (no-entry share {pc(*none_t['disagree'], 0)}% there, {pc(*none_t['split'], 0)}% {TIERS[1][1]}, {pc(*none_t['agree'], 0)}% {TIERS[2][1]}).")
L += ["", "## Limitation: one person's hand labels disagree with the corpus's categories", "", LIM]

def kinds_of(p):
    """'No entry fits' rows split into kinds: WITH-AI by step 4's attacker-objective rule, ON-AI by the corpus attack vector; two or more kinds under MIN_KIND records pooled."""
    k = collections.defaultdict(list)
    for i, r in NONE[p]: k[("no objective stated" if objective(i) == "unstated" else objective(i)) if p == "WITH-AI" else (r.get("attack_vector") or "no vector")].append((i, r))
    small = sorted(v for v, rs in k.items() if len(rs) < MIN_KIND)
    if len(small) < 2: return dict(sorted(k.items(), key=lambda x: (-len(x[1]), x[0])))
    out = {v: rs for v, rs in k.items() if len(rs) >= MIN_KIND}
    ones = [v for v in small if len(k[v]) == 1]; named = ", ".join(f"{v} {len(k[v])}" for v in sorted(small, key=lambda v: (-len(k[v]), v)) if len(k[v]) > 1)
    out[f"{len(small)} {'vectors' if p == 'ON-AI' else 'objectives'} with 1–{MIN_KIND - 1} records: {named}{', ' if named and ones else ''}{f'{len(ones)} with 1' if ones else ''}"] = [x for v in small for x in k[v]]
    return dict(sorted(out.items(), key=lambda x: (x[0].startswith(f"{len(small)} "), -len(x[1]), x[0])))   # pooled kinds last
def carries(p, e, c=None):
    """Of the records the person filed under e, how many the corpus also codes with c; without c, the two corpus codes those records carry most often."""
    filed = [r for _, r, gl in GOLD[p] if e in gl]
    if c: return sum(c in llm(r) for r in filed), len(filed)
    cc = collections.Counter(x for r in filed for x in llm(r)).most_common(2)
    return "carry " + (", ".join(f"{ename(x)} {v}" for x, v in cc) or "no corpus code")
C2RV = {c: e for e, c in RV2C.items()}
top2 = [c for c, _ in sorted(CRANK["ON-AI"].items(), key=lambda x: x[1])[:2]]; h_top2 = sum(HUM["ON-AI"][C2RV[c]] for c in top2)
nocode = [(p, e) for p in POPS for e in ADDS if HUM[p][e] >= MIN_HEAD]; h_nocode = sum(HUM[p][e] for p, e in nocode)
def cell(p, e):
    c = RV2C.get(e); h = HUM[p][e]
    cr = str(CRANK[p][c]) if c and c in CRANK[p] else "—"
    hr = f"{HRANK[p][e]} ({h})" if h else "— (0)"
    car = (lambda a, b: f"{a} of {b}")(*carries(p, e, c)) if c and h else (carries(p, e) if h else "—")
    return f"{cr} | {hr} | {car}"
L += head("5.3", f"Where the corpus and the hand labels disagree: the corpus's top two ON-AI categories hold {h_top2} of {NG['ON-AI']} hand labels, {len(nocode)} labels with no corpus code hold {h_nocode}",
          f"n = {NG['ON-AI']} ON-AI and {NG['WITH-AI']} WITH-AI hand-labelled records",
          f"One row per category, the ten in vote order then the proposed additions with {MIN_HEAD}+ hand labels in either population. *Corpus rank* orders the ten by records carrying the code; "
          f"*hand-label rank (n)* orders every label the person used by count within the sample (a quota sample, so a rank, not a prevalence); *corpus also carries it* = of the records the person "
          f"filed under the entry, how many the corpus also codes with it, or, for an entry with no corpus code, the codes the corpus put on them. ‡ = channel marker (Table 5.1).",
          ["category", "ON-AI corpus rank", "ON-AI hand-label rank (n)", "ON-AI corpus also carries it", "WITH-AI corpus rank", "WITH-AI hand-label rank (n)", "WITH-AI corpus also carries it"])
for e in sorted(TEN, key=lambda e: VR[e]):
    c = RV2C[e]; L.append(f"| {ename(c)}{'‡' if c in MARKER else ''} | {cell('ON-AI', e)} | {cell('WITH-AI', e)} |")
for e in sorted((e for e in ADDS if max(HUM[p][e] for p in POPS) >= MIN_HEAD), key=lambda e: -max(HUM[p][e] for p in POPS)):
    L.append(f"| {RVN[e]} [proposed, no corpus code] | {cell('ON-AI', e)} | {cell('WITH-AI', e)} |")
L.append(f"| *No entry fits* | — | — ({NN['ON-AI']}, {pc(NN['ON-AI'], NG['ON-AI'], 0)}% of hand-labelled) | — | — | — ({NN['WITH-AI']}, {pc(NN['WITH-AI'], NG['WITH-AI'], 0)}% of hand-labelled) | — |")
rows_53 = len(TEN) + sum(1 for e in ADDS if max(HUM[p][e] for p in POPS) >= MIN_HEAD) + 1
boiler = {p: sum(note(i) != SUBSTANTIVE for i, _ in NONE[p]) for p in POPS}
def main_kinds(p, k=2): return andlist(f"{kd} {len(rs)}" for kd, rs in list(kinds_of(p).items())[:k])
kept = [(RVN[e], *carries("ON-AI", e, RV2C[e])) for e in TEN if HUM["ON-AI"][e] >= MIN_HEAD]
hi_k = max(kept, key=lambda x: x[1] / x[2]); lo_k = min(kept, key=lambda x: x[1] / x[2])
L += ["", "Why this is a limitation:", "",
      f"- *The ranks do not match.* {RVN[top_hand]}, the person's most-used ON-AI label ({HUM['ON-AI'][top_hand]}), is the corpus's {ord_(CRANK['ON-AI'][RV2C[top_hand]])}; "
      f"the corpus's first two, {andlist(ename(c) for c in top2)}, hold {h_top2} of the {NG['ON-AI']} hand labels between them.",
      f"- *The list lacks codes for what the person saw most.* {andlist(f'{RVN[e]} ({HUM[p][e]} {p} hand labels; the corpus filed them as {carries(p, e).removeprefix(chr(99)+chr(97)+chr(114)+chr(114)+chr(121)+chr(32))})' for p, e in nocode)} have no corpus code.",
      f"- *A large share fits nothing.* No entry fits {NN['ON-AI']} ON-AI ({pc(NN['ON-AI'], NG['ON-AI'], 0)}%) and {NN['WITH-AI']} WITH-AI ({pc(NN['WITH-AI'], NG['WITH-AI'], 0)}%) rows: "
      f"ON-AI mostly {main_kinds('ON-AI', 1)} (classifier evaluations), WITH-AI mostly {main_kinds('WITH-AI')} (deepfake fraud and abuse imagery; {sum(stub(r) for _, r in NONE['WITH-AI'])} of {NN['WITH-AI']} are tracker stubs). "
      f"The rubric wants an LLM mechanism: input that \"{RUB['pi']}\", output \"{RUB['mis']}\", or \"{RUB['wla']}\"; the person's notes are boilerplate on {boiler['ON-AI'] + boiler['WITH-AI']} of {NN['ON-AI'] + NN['WITH-AI']} rows. "
      f"{none_t['disagree'][0]} of the {NN['WITH-AI']} WITH-AI rows are ones the three LLM pre-labellers disagreed on, a tier the quota took in full.",
      f"- *Where the person did use a corpus category, the corpus usually has it too* ({hi_k[0]} {hi_k[1]} of {hi_k[2]}; lowest {lo_k[0]} {lo_k[1]} of {lo_k[2]}), so the disagreement is in what the corpus adds in bulk and what it cannot name, not in the person rejecting its codes."]

# ---------------------------------------------------------------- Use cases
ioh, mcp = "LLM10", next(e for e, n in RVN.items() if n.startswith("MCP"))
pi = RV2C[TEN[0]]; d_ioh = demo_share("ON-AI", ioh); d_pi = demo_share("ON-AI", pi)
ioh_seed = sum(r.get("attack_vector") in seed_vectors(ioh) for r in P["ON-AI"] if ioh in llm(r))
mcp_sc = carries("ON-AI", mcp, "LLM04")
USE = [f"- *Deployers.* {ename(ioh)}'s ON-AI {signed(PLACES['ON-AI'][C2RV[ioh]])} is rule output: {ioh_seed} of {d_ioh[1]} records carry a code-injection seed vector, "
       f"{pc(*d_ioh, 0)}% demonstrations (Table 5.1).",
       f"- *Researchers.* {ename(pi)}, the vote's first, ranks {ord_(CRANK['ON-AI'][pi])} in ON-AI; {HUM['ON-AI'][mcp]} {RVN[mcp]} rows ({mcp_sc[0]} corpus-filed as "
       f"{ename('LLM04')}) seed sampling (Table 5.3).",
       f"- *Framework authors.* {NN['WITH-AI']} of {NG['WITH-AI']} WITH-AI hand labels fit no entry and {RVN[WLA]}, {HUM['WITH-AI'][WLA]} labels, has no corpus code: "
       f"deepfake fraud has no LLM mechanism (Table 5.3)."]
L += ["", "## Use cases", "", *USE, "",
      "**Not supported:** prevalence; a corrected Top 10; attack chains; trends; attribution or exploitation status; statements about how attackers operated."]

# ---------------------------------------------------------------- Limitations of the data
frame = {x: collections.Counter(S[i]["population"] for i in S if S[i]["source_class"] == x and S[i]["population"] in ("ON-AI", "WITH-AI", "BOTH")) for x in CHANNELS}
ADV = re.compile(r"attacker|threat actor|hacker|adversar|campaign|exploited|abused|scam|fraud|extort|stole|breach|malicious|\bAPT\b|state-sponsored|cybercrim|ransomware|phish|impersonat|weaponi[sz]", re.I)
wv = [C[i] for i in S if S[i]["rule"] == "with-vector"]; wv_silent = sum(not ADV.search(text(r)) for r in wv)
_NA, _NW = "no attacker: operator harm or model failure (misplaced record)", "none: conventional exploit record misplaced in WITH-AI"
_on = [i for i in S if S[i]["population"] == "ON-AI"]; _wi = [i for i in S if S[i]["population"] == "WITH-AI"]
LEAK = {"on": len(_on), "wi": len(_wi), "on_na": sum(METH[i]["entry_point"] == _NA for i in _on), "wi_na": sum(METH[i]["ai_role"] == _NA for i in _wi),
        "on_other": sum(METH[i]["entry_point"] == "other" for i in _on), "wi_cve": sum(METH[i]["ai_role"] == _NW for i in _wi)}   # step 4's reviewed values
LIMS = [f"- Labels are rule outputs: {pc(*seed_share(R))}% of OWASP codes come from the attack_vector seed, the rest from ingest records (Tables 5.1, 5.2).",
        f"- {ename('LLM04')} marks the CVE channel and {frame['cve/ghsa']['ON-AI']:,} of {sum(frame['cve/ghsa'].values()):,} cve/ghsa frame records are ON-AI, so pooled comparisons compare channels (Tables 1.10, 2.2).",
        f"- One coder hand-labelled a quota sample: {NG['ON-AI']} ON-AI and {NG['WITH-AI']} WITH-AI rows (Tables 1.14, 5.3).",
        f"- The split is rule-based: {wv_silent:,} of {len(wv):,} vector-only WITH-AI rows name no adversary (Table 2.5). Step 4's review of every record found "
        f"{LEAK['on_na']} ON-AI ({pc(LEAK['on_na'], LEAK['on'])}%) and {LEAK['wi_na']} WITH-AI ({pc(LEAK['wi_na'], LEAK['wi'])}%) records that describe no adversary, "
        f"{LEAK['on_other']} ON-AI records whose entry point fits no value (such as an AI-assisted scam on people) and {LEAK['wi_cve']} CVE records in WITH-AI; they stay in the counts above (Tables 4.1, 4.4).",
        f"- Join losses: {g_lost} of {len(gold_ids):,} hand-labelled rows have no current record of their own (Table 1.13).",
        f"- Vote–data concordance is weak: weighted κ {KAPPA:.2f} ({sg(KCI[0])} to {sg(KCI[1])}) (Table 1.15).",
        f"- The two OWASP numberings differ on {diff_codes} of ten entries, so joins use names (Table 1.0).",
        f"- The public record is a small, self-selected sample: only {pc(sum(frame['cve/ghsa'].values()), sum(1 for i in S if S[i]['source_class'] == 'cve/ghsa'))}% of CVE/GHSA records "
        f"and {pc(sum(frame['harm-db'].values()), sum(1 for i in S if S[i]['source_class'] == 'harm-db'))}% of harm-database records involve an adversary at all, `exploited_in_wild` is set on "
        f"{sum(r.get('exploited_in_wild') is True for r in R)} records, and attacks that are never disclosed, settled privately or seen only in vendor telemetry are absent (Tables 2.2, 4.0).",
        f"- The index pools trackers with different units: a CVE is one bug in one product, a harm-database row is one news event, a research row is one paper; counts across them, and the "
        f"corpus's own merging of {sum(len(r['source_ids']) > 1 for r in R):,} multi-source records, mix units (Table 1.1).",
        "- Record year, date precision, stubs and empty fields: steps 1, 2 and 4."]
L += ["", "## Limitations of the data", "", *LIMS]
write("s05_techniques.md", L)
print(f"Table 5.3 rows: {rows_53}; words: limitation {words(LIM)}, use cases {words(' '.join(USE))}, limitations {words(' '.join(LIMS))}")
