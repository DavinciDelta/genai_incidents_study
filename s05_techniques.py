#!/usr/bin/env python3
"""s05_techniques.py — Step 5. One question: which OWASP LLM Top 10 categories stand out in each population against the OWASP
community vote. Two sources: the corpus's OWASP codes (keyword labels) and rank-validation's report of the community vote. The
populations keep every record; those step 4's review could not place as attacks are counted separately in each category. One annotator's hand labels (from incident-rank-validation) show attacks the OWASP list cannot name: a limitation, one table per
population. It also hosts the study's Use cases and Limitations of the data. Step 4 answers HOW attacks happened; this file does not repeat it.

Everything here is a corpus keyword label or a read of another project's artifacts; nothing is coded from reports yet.
llm() is where hand codes replace the corpus labels in the next phase.
Output: out/s05_techniques.md
"""
import ast, collections, json, re
from common import load_full, load_rv, join_rv, load_prelabels, owasp_names, source_class, text, write, READ, OUT, EXT, CYCLE, CHANNELS

S = json.load(open(OUT / "split.json")); C = load_full(); R = list(C.values())
rv = load_rv(); JR = join_rv(C, rv); J = JR["rows"]; PRE = load_prelabels()
NM = owasp_names(rv); RV2C, C2RV, RVN = NM["rv2corpus"], NM["corpus2rv"], NM["rv"]
POPS = ("ON-AI", "WITH-AI")
METH = json.load(open(OUT / "methodology.json"))      # step 4's reviewed labels: they clean the populations, and the WITH-AI 'No entry fits' kinds are its objective
NO_ATT, NONE_W = "no attacker: operator harm or model failure (misplaced record)", "none: conventional exploit record misplaced in WITH-AI"
def unplaced(i, p):
    """Step 4's review found no adversary (both populations), or a conventional-exploit record with no AI medium (WITH-AI). Such records stay in every table and are counted separately."""
    m = METH.get(i, {}); return m.get("entry_point") == NO_ATT if p == "ON-AI" else m.get("ai_role") in (NO_ATT, NONE_W)
RAW = {p: [i for i, s in S.items() if s["population"] == p] for p in POPS}
P = {p: [C[i] for i in RAW[p]] for p in POPS}; OUTN = {p: sum(unplaced(i, p) for i in RAW[p]) for p in POPS}
DEMO = ("research", "research-demonstrated", "red-team")
MIN_RECORDS = 30     # below this many corpus records a category is marked § and left out of the titles and 'What stands out' bullets
SMALL = "§"
MARKER_SHARE = 0.9   # a code is a channel marker (‡) when it sits on this share of one channel's records, or of its own assignments
MIN_HAND = 2         # a category or proposed addition gets its own row in Tables 5.4a–b from this many hand labels; smaller ones are pooled
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
def mark(p, c):
    """‡ only where the code's marker channel still has records in this population (after step 4's cleaning WITH-AI has no cve/ghsa records)."""
    return "‡" if c in MARKER and any(source_class(r) == MARKER[c][2] for r in P[p]) else ""
def demo_share(p, c): rows = [r for r in P[p] if c in llm(r)]; return sum(r["category"] in DEMO for r in rows), len(rows)
diff_codes = sum(C2RV[c] != c for c in NM["corpus"])

# ---------------------------------------------------------------- opener
L = ["# Step 5 — Which attack categories stand out against the community vote", "",
     f"Generated by `s05_techniques.py` (`make s05`); do not edit by hand; inputs pinned in `external/PINS.json`. {READ}", "",
     f"Which OWASP LLM Top 10 categories does each population rank higher or lower than the community vote? Two sources: the corpus's OWASP categories "
     f"and the community vote with its 90% interval as rank-validation reports ({len(ENTRIES)} candidates ranked by respondents; its data rank is Table 1.15). "
     f"Hand labels from one annotator of incident-rank-validation (a separate project that tests the OWASP ranking) show attacks the list cannot name: a limitation below (Tables 5.4a–b).", "",
     f"Every record stays in: {len(P['ON-AI']):,} ON-AI and {len(P['WITH-AI']):,} WITH-AI. Step 4's review could not place {OUTN['ON-AI']} ON-AI and {OUTN['WITH-AI']} WITH-AI records "
     f"as attacks (no adversary described, or a conventional-exploit record misplaced in WITH-AI); they are counted like the rest, and Tables 5.1–5.2 show how many of each category's records they are. "
     f"The OWASP categories themselves are the corpus's, set by keyword rules (Limitations of the data); step 4's reviewed labels answer how the attacks happened."]

# ---------------------------------------------------------------- Tables 5.1 / 5.2
UNP = {p: collections.Counter(c for i in RAW[p] if unplaced(i, p) for c in set(llm(C[i]))) for p in POPS}   # per code: records the review could not place
def category_table(p, num):
    rows, n, on = P[p], len(P[p]), p == "ON-AI"; cnt, crank, places = CNT[p], CRANK[p], PLACES[p]
    big = [e for e in places if cnt[RV2C[e]] >= MIN_RECORDS]
    top, bot = max(places[e] for e in big), min(places[e] for e in big)
    his = [e for e in big if places[e] == top]; los = [e for e in big if places[e] == bot]; hi = his[0]
    nm = lambda es: andlist(ename(RV2C[e]) for e in es)
    cols = ["category [corpus code]", "vote rank (90% interval)", "corpus records n (%)", "corpus rank", "places above the vote", "of which not placed as attacks by the review"] + (["demonstrated, % of its records"] if on else [])
    if on:
        desc = (f"Rows: the ten categories in vote order; codes are the corpus's, not OWASP's (Table 1.0). *Corpus rank* orders them by {p} records carrying the code; "
                f"*places above the vote* = vote rank − corpus rank (+ = the corpus ranks it higher); {SMALL} = under {MIN_RECORDS} corpus records, outside title and "
                f"bullets; *not placed as attacks* = records step 4's review found describe no adversary (or, in WITH-AI, are conventional-exploit records misplaced there), kept in the counts; "
                f"*demonstrated* = research, research-demonstrated or red-team. {MARKER_DEF}.")
    else:
        wd = sum(r["category"] in DEMO for r in rows)
        desc = (f"The OWASP list scopes LLM applications; records where the AI is the attacker's instrument fall outside it by design. Columns as in Table 5.1 "
                f"minus *demonstrated* ({p} has {wd} demonstration record{'s' * (wd != 1)}).")
    L.extend(head(num, f"{p}, categories with {MIN_RECORDS}+ records: {nm(his)} {signed(top)} places above its vote rank, {nm(los)} {signed(bot)}", f"n = {n:,} {p} records", desc, cols))
    for e in TEN:
        c = RV2C[e]; lo_, hi_ = VCI[e]; d, b = demo_share(p, c)
        L.append(f"| {code(c)}{mark(p, c)} | {VR[e]:g} ({lo_:g}–{hi_:g}) | {npc(cnt[c], n)}{SMALL if cnt[c] < MIN_RECORDS else ''} | {crank.get(c, '—')} | "
                 f"{signed(places[e]) if e in places else '—'} | {UNP[p][c]} |" + (f" {pc(d, b, 0)} |" if on else ""))
    def why(e):
        c = RV2C[e]; d, b = demo_share(p, c)
        if mark(p, c): return " (channel marker ‡)"
        av = collections.Counter(r.get("attack_vector") or "none" for r in rows if c in llm(r)).most_common(1)[0]
        return " (" + "; ".join(([f"{pc(d, b, 0)}% demonstrations"] if on else []) + [f"seeded from {', '.join(seed_vectors(c))}", f"top vector on its records: {av[0]}, {av[1]} of {b}"]) + ")"
    marks = [c for c in sorted(MARKER) if cnt[c] >= MIN_RECORDS and mark(p, c)]
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
def avg_ranks(vals, reverse=False):
    """Ranks 1..n of a list (1 = smallest, or largest with reverse), ties sharing the mean of their positions."""
    order = sorted(range(len(vals)), key=lambda i: vals[i], reverse=reverse); r = [0.0] * len(vals); k = 0
    while k < len(order):
        j = k
        while j + 1 < len(order) and vals[order[j + 1]] == vals[order[k]]: j += 1
        for t in range(k, j + 1): r[order[t]] = (k + j) / 2 + 1
        k = j + 1
    return r
def spearman(xs, ys):
    """Spearman's ρ: the Pearson correlation of the two lists' ranks within the compared set; None below 3 pairs."""
    n = len(xs)
    if n < 3: return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys)); sxx = sum((x - mx) ** 2 for x in xs); syy = sum((y - my) ** 2 for y in ys)
    return sxy / (sxx * syy) ** 0.5 if sxx and syy else None
YEAR = 2026
P26 = {p: [r for r in P[p] if r["year"] == YEAR] for p in POPS}
CNT26 = {p: collections.Counter(c for r in P26[p] for c in set(llm(r))) for p in POPS}; CRANK26 = {p: ranks(CNT26[p]) for p in POPS}
COMMON = {p: [e for e in TEN if CNT[p][RV2C[e]] >= MIN_RECORDS and CNT26[p][RV2C[e]] >= MIN_RECORDS] for p in POPS}   # the same categories in both cuts
def rho(p, cnt):
    es = COMMON[p]; return spearman(avg_ranks([VR[e] for e in es]), avg_ranks([cnt[RV2C[e]] for e in es], reverse=True))
RHO = {p: (rho(p, CNT[p]), rho(p, CNT26[p])) for p in POPS}
fr = lambda v: "—" if v is None else f"{v:+.2f}".replace("-", "−")
sh = lambda p, c, cut: round(100 * (CNT26 if cut else CNT)[p][c] / len(P26[p] if cut else P[p]), 1)    # share of records carrying c, as printed
chg = lambda x: "0.0" if round(x, 1) == 0 else f"{x:+.1f}".replace("-", "−")
N26_ALL = sum(C[i]["year"] == YEAR for p in POPS for i in RAW[p])
for p, sub in (("ON-AI", "a"), ("WITH-AI", "b")):
    a_, b_ = RHO[p]
    plain = [RV2C[e] for e in TEN if CNT[p][RV2C[e]] >= MIN_RECORDS and CNT26[p][RV2C[e]] >= MIN_RECORDS and not mark(p, RV2C[e])]
    heads_ = sorted(plain, key=lambda c: -abs(sh(p, c, 1) - sh(p, c, 0)))[:2]
    L += head(f"5.3{sub}", f"{p}: share of records per category, all years vs {YEAR}; " + "; ".join(f"{ename(c)} {sh(p, c, 0):.1f}% vs {sh(p, c, 1):.1f}%" for c in heads_),
              f"n = {len(P[p]):,} records, {len(P26[p]):,} of them dated {YEAR}",
              (f"Share of records carrying each category, all years and {YEAR} only ({YEAR} records are part of all years); rows in vote order. A record can carry several categories, "
               f"so a column adds past 100%. *Change* = {YEAR} − all years, from the shares as printed. § = under {MIN_RECORDS} records in that cut. "
               f"‡ = channel marker (defined under Table 5.1): the share moves with that channel's size." if sub == "a" else "Columns as in Table 5.3a."), 
              ["category", "vote rank", "all years, % of records", f"{YEAR}, % of records", "change (points)"])
    for e in TEN:
        c = RV2C[e]
        L.append(f"| {ename(c)}{mark(p, c)} | {VR[e]:g} | {sh(p, c, 0):.1f}{SMALL if CNT[p][c] < MIN_RECORDS else ''} | "
                 f"{sh(p, c, 1):.1f}{SMALL if CNT26[p][c] < MIN_RECORDS else ''} | {chg(sh(p, c, 1) - sh(p, c, 0))} |")
    n_c = len(COMMON[p])
    L += ["", (f"Closer to the vote in {YEAR}? On the {n_c} categories with {MIN_RECORDS}+ records in both cuts, Spearman's ρ between the vote's order and the order of the shares "
               f"is {fr(a_)} all years and {fr(b_)} in {YEAR} (+1 = the vote's order, 0 = unrelated, −1 = reversed): "
               + ("no closer" if b_ <= a_ else "slightly closer" if b_ - a_ < 0.3 else "closer") + f". With {n_c} categories, ρ moves a long way when one category changes place."
               if a_ is not None and b_ is not None else
               f"Closer to the vote in {YEAR}? Only {n_c} categories have {MIN_RECORDS}+ records in both cuts, too few to compare the order with the vote.")]
cvesh = lambda rows: 100 * sum(source_class(r) == "cve/ghsa" for r in rows) / len(rows)
L += ["", f"The {YEAR} column is not a test of the vote: the vote ranks expected risk, not disclosed records; {YEAR} ON-AI records are {cvesh(P26['ON-AI']):.0f}% cve/ghsa against "
          f"{cvesh(P['ON-AI']):.0f}% for all years, so the ‡ rows move with the channel mix; "
          f"and the record year is often the ingestion year (Table 1.5). `out/dataset_post_{YEAR}.csv` lists all {N26_ALL:,} records dated {YEAR}; "
          f"of these, {len(P26['ON-AI']):,} are ON-AI and {len(P26['WITH-AI']):,} WITH-AI."]

# ---------------------------------------------------------------- Limitation: the hand labels (Tables 5.4a–b)
TIERS = (("disagree", "disagreement rows"), ("split", "where two pre-labellers agreed"), ("agree", "where three did"))
GW = GOLD["WITH-AI"]
none_t = {t: (sum(gl == [] for i, _, gl in GW if tier_of(i) == t), sum(tier_of(i) == t for i, _, _ in GW)) for t, _ in TIERS}
top_hand = max(TEN, key=lambda e: (HUM["ON-AI"][e], -VR[e]))
heads = {p: sorted((e for e in ADDS if HUM[p][e] >= MIN_HEAD), key=lambda e: -HUM[p][e]) for p in POPS}
def ord_(k): return f"{k}{'th' if 10 <= k % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(k % 10, 'th')}"
LIM = (f"One annotator of incident-rank-validation hand-labelled {NG['ON-AI']} ON-AI and {NG['WITH-AI']} WITH-AI records. The records were drawn by quota "
       f"(every record the project's three LLM pre-labellers disagreed on, then {q3} unanimous and {q2} majority records per category), so the counts describe the sample, not prevalence. "
       f"Tables 5.4a–b show, for each category the annotator used, how often the corpus files the same record under it.")
L += ["", "## Limitation: hand labels show attacks the OWASP categories cannot name", "", LIM]

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
def agree_cell(p, e):
    c = RV2C.get(e)
    if c: a_, b_ = carries(p, e, c); return f"{a_} of {b_}"
    filed = [r for _, r, gl in GOLD[p] if e in gl]
    return f"no corpus code; most common corpus codes on these {len(filed)}: " + carries(p, e).removeprefix("carry ") + " (a record can carry several)"
nfmt = lambda p, n: f"{n} ({pc(n, NG[p], 0)}%)"
for p, sub in (("ON-AI", "a"), ("WITH-AI", "b")):
    shown = sorted((e for e in ENTRIES if HUM[p][e] and (e in TEN or HUM[p][e] >= MIN_HEAD)), key=lambda e: (-HUM[p][e], VR.get(e, 99)))
    rest = [e for e in ADDS if HUM[p][e] and e not in shown]
    lab = lambda e: f"{RVN[e]}{'' if RV2C.get(e) else ' (proposed)'}"
    n_prop = sum(HUM[p][e] for e in ADDS)
    L += head(f"5.4{sub}", f"{p} hand labels: {pc(n_prop, NG[p], 0)}% of the sampled records fall in proposed categories the corpus has no code for; {pc(NN[p], NG[p], 0)}% fit no category",
              f"n = {NG[p]} hand-labelled {p} records",
              (f"Rows: the categories the annotator used, most-used first; proposed categories under {MIN_HEAD} records are pooled. Each record has one category or none, so the rows add to n. "
               "*Corpus files them there too* = of those records, how many the corpus also gives that category. *(proposed)* = a category the annotator's project added to the OWASP list; "
               "the corpus has no code for it, so the last column gives the corpus codes those records carry most often." if sub == "a" else "Columns as in Table 5.4a."),
              ["category", "hand-labelled records n (%)", "corpus files them there too"])
    for e in shown:
        L.append(f"| {lab(e)} | {nfmt(p, HUM[p][e])} | {agree_cell(p, e)} |")
    if rest: L.append(f"| {len(rest)} other proposed categor{'y' if len(rest) == 1 else 'ies'} | {nfmt(p, sum(HUM[p][e] for e in rest))} | no corpus code |")
    L.append(f"| *No category fits* | {nfmt(p, NN[p])} | — ({sum(unplaced(i, p) for i, _ in NONE[p])} of them not placed as attacks by step 4's review) |")
def kind_list(p, k):
    return andlist(f"{kd} ({len(rs)} of {NN[p]})" for kd, rs in list(kinds_of(p).items())[:k])
kept_ = [(RVN[e], *carries("ON-AI", e, RV2C[e])) for e in TEN if HUM["ON-AI"][e] >= MIN_HEAD]
hi_k = max(kept_, key=lambda x: x[1] / x[2]); lo_k = min(kept_, key=lambda x: x[1] / x[2])
small_k = sorted(((RVN[e], *carries("ON-AI", e, RV2C[e])) for e in TEN if 0 < HUM["ON-AI"][e] < MIN_HEAD), key=lambda x: x[1] / x[2])[:2]
L += ["", "Why this is a limitation:", "",
      f"- *Missing categories.* {andlist(f'{RVN[e]} ({HUM[p][e]} {p} records)' for p, e in nocode)} have no corpus code, so the corpus files those records under other categories (Tables 5.4a–b).",
      f"- *Nothing fits.* {pc(NN['ON-AI'], NG['ON-AI'], 0)}% of ON-AI and {pc(NN['WITH-AI'], NG['WITH-AI'], 0)}% of WITH-AI hand-labelled records fit no category. "
      f"In ON-AI the largest group by corpus attack vector is {kind_list('ON-AI', 1)}; in WITH-AI, by step 4's objective, {kind_list('WITH-AI', 2)}; "
      f"{sum(stub(r) for _, r in NONE['WITH-AI'])} of the {NN['WITH-AI']} WITH-AI records are tracker stubs. The list asks for an LLM mechanism, such as input that \"{RUB['pi']}\", "
      f"which deepfake abuse imagery, political deepfakes and classifier evaluations lack.",
      f"- *Where both use an OWASP category with {MIN_HEAD}+ hand labels, they mostly agree* ({hi_k[0]} {hi_k[1]} of {hi_k[2]}; lowest {lo_k[0]} {lo_k[1]} of {lo_k[2]}); "
      f"on smaller rows less so ({', '.join(f'{a} {b} of {c}' for a, b, c in small_k)}). The larger gap is the attacks the list cannot name (the proposed rows) and the records that fit nothing."]

# ---------------------------------------------------------------- Use cases
ioh, mcp = "LLM10", next(e for e, n in RVN.items() if n.startswith("MCP"))
pi = RV2C[TEN[0]]; d_ioh = demo_share("ON-AI", ioh); d_pi = demo_share("ON-AI", pi)
ioh_seed = sum(r.get("attack_vector") in seed_vectors(ioh) for r in P["ON-AI"] if ioh in llm(r))
mcp_sc = carries("ON-AI", mcp, "LLM04")
USE = [f"- *Deployers.* {ename(ioh)}'s ON-AI {signed(PLACES['ON-AI'][C2RV[ioh]])} is rule output: {ioh_seed} of {d_ioh[1]} records carry a code-injection seed vector, "
       f"{pc(*d_ioh, 0)}% demonstrations (Table 5.1).",
       f"- *Researchers.* {ename(pi)}, the vote's first, ranks {ord_(CRANK['ON-AI'][pi])} in ON-AI. The {HUM['ON-AI'][mcp]} records the annotator filed as {RVN[mcp]} "
       f"(the corpus files {mcp_sc[0]} of them under {ename('LLM04')}) are a starting sample for that proposed category (Table 5.4a).",
       f"- *Framework authors.* {NN['WITH-AI']} of {NG['WITH-AI']} hand-labelled WITH-AI records fit no category, and {RVN[WLA]} ({HUM['WITH-AI'][WLA]} records) has no corpus code: "
       f"deepfake abuse imagery and political deepfakes have no LLM mechanism (Table 5.4b)."]
L += ["", "## Use cases", "", *USE, "",
      "**Not supported:** prevalence; a corrected Top 10; attack chains; trends (Tables 5.3a–b set one year beside all years, and the record year is often the ingestion year); "
      "attribution or exploitation status; statements about how attackers operated."]

# ---------------------------------------------------------------- Limitations of the data
frame = {x: collections.Counter(S[i]["population"] for i in S if S[i]["source_class"] == x and S[i]["population"] in ("ON-AI", "WITH-AI", "BOTH")) for x in CHANNELS}
_NA, _NW = "no attacker: operator harm or model failure (misplaced record)", "none: conventional exploit record misplaced in WITH-AI"
_on = [i for i in S if S[i]["population"] == "ON-AI"]; _wi = [i for i in S if S[i]["population"] == "WITH-AI"]
LEAK = {"on": len(_on), "wi": len(_wi), "on_na": sum(METH[i]["entry_point"] == _NA for i in _on), "wi_na": sum(METH[i]["ai_role"] == _NA for i in _wi),
        "on_other": sum(METH[i]["entry_point"] == "other" for i in _on), "wi_cve": sum(METH[i]["ai_role"] == _NW for i in _wi)}   # step 4's reviewed values
_src = ast.parse((EXT / "corpus_merge_and_dedupe.py").read_text())
N_AV_RULES = next(len(n.value.elts) for n in _src.body if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", "") == "_ATTACK_VECTOR_RULES")   # read, never run
LIMS = [f"- The corpus's labels are keyword rules: when a source gives no attack vector, `classify_attack_vector` in the corpus build script takes the first of {N_AV_RULES} regular expressions "
        f"that matches the title and description (for example 'impersonat' → deepfake); records that arrive without OWASP codes get them from the attack vector by a fixed table "
        f"({pc(*seed_share(R))}% of OWASP codes equal that seed), and ATLAS codes follow from the OWASP codes by lookup (Tables 1.10, 5.1, 5.2).",
        f"- {ename('LLM04')} marks the CVE channel and {frame['cve/ghsa']['ON-AI']:,} of {sum(frame['cve/ghsa'].values()):,} cve/ghsa frame records are ON-AI, so pooled comparisons compare channels (Tables 1.10, 2.2).",
        f"- One annotator hand-labelled a quota sample: {NG['ON-AI']} ON-AI and {NG['WITH-AI']} WITH-AI records (Tables 1.14, 5.4a–b).",
        f"- Step 2's split is rule-based; Table 2.5 lists its weak spots. Step 4's review of every record found "
        f"{LEAK['on_na']} ON-AI ({pc(LEAK['on_na'], LEAK['on'])}%) and {LEAK['wi_na']} WITH-AI ({pc(LEAK['wi_na'], LEAK['wi'])}%) records that describe no adversary, "
        f"{LEAK['on_other']} ON-AI records whose entry point fits no value (such as an AI-assisted scam on people) and {LEAK['wi_cve']} conventional-exploit records misplaced in WITH-AI; this step keeps "
        f"all of them in its counts and shows them per category (Tables 4.1, 4.4, 5.1, 5.2).",
        f"- Join losses: {g_lost} of {len(gold_ids):,} hand-labelled rows have no current record of their own (Table 1.13).",
        f"- Vote–data concordance is weak: weighted κ {KAPPA:.2f} ({sg(KCI[0])} to {sg(KCI[1])}) (s01 section 0, 'data rank'; Table 1.15).",
        f"- The two OWASP numberings differ on {diff_codes} of ten entries, so joins use names (Table 1.0).",
        f"- The public record is a small, self-selected sample: only {pc(sum(frame['cve/ghsa'].values()), sum(1 for i in S if S[i]['source_class'] == 'cve/ghsa'))}% of CVE/GHSA records "
        f"and {pc(sum(frame['harm-db'].values()), sum(1 for i in S if S[i]['source_class'] == 'harm-db'))}% of harm-database records involve an adversary at all, `exploited_in_wild` is set on "
        f"{sum(r.get('exploited_in_wild') is True for r in R)} records, and attacks that are never disclosed, settled privately or seen only in vendor telemetry are absent (Tables 2.2, 2.5).",
        f"- The index pools trackers with different units: a CVE is one bug in one product, a harm-database row is one news event, a research row is one paper; counts across them, and the "
        f"corpus's own merging of {sum(len(r['source_ids']) > 1 for r in R):,} multi-source records, mix units (s01 section B; Table 1.1).",
        "- Record year, date precision, stubs and empty fields: steps 1, 2 and 4."]
L += ["", "## Limitations of the data", "", *LIMS]
write("s05_techniques.md", L)
print(f"words: limitation {words(LIM)}, use cases {words(' '.join(USE))}, limitations {words(' '.join(LIMS))}")
