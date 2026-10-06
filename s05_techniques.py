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
L += head("5.3", "Hand labels vs corpus labels, both populations",
          f"n = {NG['ON-AI']} ON-AI and {NG['WITH-AI']} WITH-AI hand-labelled records of {g_rec:,} joined; the rest NONE {g_pop['NONE']}, BOTH {g_pop['BOTH']}, UNRESOLVED {g_pop['UNRESOLVED']}",
          f"Per population: categories in corpus-rank order (under {MIN_HAND} hand labels: pooled); proposed additions (rank-validation's candidates) with {MIN_HAND}+ hand "
          f"labels, note = corpus codes on their records (several per record possible); *No entry fits* by kind (↳ ON-AI by corpus "
          f"attack vector, WITH-AI by step 4's objective rule; kinds under {MIN_KIND} records pooled; lowest-id example). *Hand-label rank*: by count within the sample, "
          f"ties shared; *a of b*: of b records the person filed under the entry, a also carry its corpus code; tracker stub: description is only a tracker "
          f"pointer (step 4); ‡ as in Table 5.1.",
          ["population", "category", "corpus rank", "corpus records n", "hand labels n", "hand-label rank (sample)", "corpus also carries it (a of b)", "note"])
rows_53 = 0
for p in POPS:
    hum, crank, cnt, hr = HUM[p], CRANK[p], CNT[p], HRANK[p]
    order = sorted(TEN, key=lambda e: (crank.get(RV2C[e], 99), VR[e])); few = [e for e in order if hum[e] < MIN_HAND]
    for e in order:
        c = RV2C[e]; a, b = carries(p, e, c)
        if hum[e] >= MIN_HAND:
            L.append(f"| {p} | {ename(c)}{'‡' if c in MARKER else ''} | {crank.get(c, '—')} | {cnt[c]:,} | {hum[e]} | {hr.get(e, '—')} | {a} of {b} | {'‡ channel marker' if c in MARKER else ''} |")
    def few_note(e):
        c = RV2C[e]; a, b = carries(p, e, c)
        return f"{ename(c)}{'‡' if c in MARKER else ''} (rank {crank.get(c, '—')}) {hum[e]}, {a} of {b}"
    zero = [e for e in few if not hum[e]]; some = "; ".join(few_note(e) for e in few if hum[e])
    none_ = ("none on " + ", ".join(f"{ename(RV2C[e])}{'‡' if RV2C[e] in MARKER else ''}" for e in zero)) if zero else ""
    L.append(f"| {p} | *{len(few)} categories with under {MIN_HAND} hand labels* | — | {sum(cnt[RV2C[e]] for e in few):,} | {sum(hum[e] for e in few)} | — | — | {'; '.join(x for x in (some, none_) if x)} |")
    adds = [e for e in ADDS if hum[e] >= MIN_HAND]; pooled = [e for e in ADDS if e not in adds]
    for e in sorted(adds, key=lambda e: -hum[e]):
        L.append(f"| {p} | {RVN[e]} [proposed] | — | — | {hum[e]} | {hr[e]} | — | {carries(p, e)} |")
    L.append(f"| {p} | *{len(pooled)} other proposed additions* | — | — | {sum(hum[e] for e in pooled)} | — | — | "
             f"{', '.join(f'{RVN[e]} {hum[e]}' for e in pooled if hum[e]) or 'none'}; {sum(not hum[e] for e in pooled)} with none |")
    st_all = sum(stub(r) for _, r in NONE[p]); kinds = kinds_of(p)
    onv = sum(S[i]["rule"] == "on-vector" for i, _ in NONE[p])
    how = f"{onv} of {NN[p]} ON-AI by vector alone (step 2's on-vector rule); " if p == "ON-AI" else ""
    L.append(f"| {p} | *No entry fits* | — | — | {NN[p]} ({pc(NN[p], NG[p])}% of {NG[p]}) | — | — | {st_all} of {NN[p]} tracker stubs; {how}{len(kinds)} kinds below |")
    for kd, rs in kinds.items():
        i, r = min(rs, key=lambda x: x[0]); st = sum(stub(x) for _, x in rs)
        flag = f"{st} of {len(rs)} tracker stubs; " if kd == "no objective stated" else ""
        L.append(f"| {p} | ↳ {kd} | — | — | {len(rs)} | — | — | {flag}e.g. {i}: {cut(r['title'])} |")
    rows_53 += len(TEN) - len(few) + 1 + len(adds) + 2 + len(kinds)
boiler = {p: sum(note(i) != SUBSTANTIVE for i, _ in NONE[p]) for p in POPS}
WHY = (f"*Why the person placed these nowhere.* Rubric: an LLM mechanism, input that \"{RUB['pi']}\", output \"{RUB['mis']}\", or \"{RUB['wla']}\". Notes are boilerplate or "
       f"empty on {boiler['ON-AI']}/{NN['ON-AI']} ON-AI and {boiler['WITH-AI']}/{NN['WITH-AI']} WITH-AI rows, else \"{SUBSTANTIVE}\" This study's reading: ON-AI, "
       f"{READING['ON-AI']}; WITH-AI, {READING['WITH-AI']}.")
L += ["", WHY]

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
LIMS = [f"- Labels are rule outputs: {pc(*seed_share(R))}% of OWASP codes come from the attack_vector seed, the rest from ingest records (Tables 5.1, 5.2).",
        f"- {ename('LLM04')} marks the CVE channel and {frame['cve/ghsa']['ON-AI']:,} of {sum(frame['cve/ghsa'].values()):,} cve/ghsa frame records are ON-AI, so pooled comparisons compare channels (Tables 1.10, 2.2).",
        f"- One coder hand-labelled a quota sample: {NG['ON-AI']} ON-AI and {NG['WITH-AI']} WITH-AI rows (Tables 1.14, 5.3).",
        f"- The split is rule-based: {wv_silent:,} of {len(wv):,} vector-only WITH-AI rows name no adversary (Table 2.5).",
        f"- Join losses: {g_lost} of {len(gold_ids):,} hand-labelled rows have no current record of their own (Table 1.13).",
        f"- Vote–data concordance is weak: weighted κ {KAPPA:.2f} ({sg(KCI[0])} to {sg(KCI[1])}) (Table 1.15).",
        f"- The two OWASP numberings differ on {diff_codes} of ten entries, so joins use names (Table 1.0).",
        "- Record year, date precision, stubs and empty fields: steps 1, 2 and 4."]
L += ["", "## Limitations of the data", "", *LIMS]
write("s05_techniques.md", L)
print(f"Table 5.3 rows: {rows_53}; words: limitation {words(LIM)}, why {words(WHY)}, use cases {words(' '.join(USE))}, limitations {words(' '.join(LIMS))}")
