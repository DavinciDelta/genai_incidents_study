#!/usr/bin/env python3
"""s05_techniques.py — Step 5. One question: which OWASP LLM Top 10 categories stand out in each population against the OWASP
community vote, and what one person's hand labels (rank-validation's adjudicator) say about them. Runs last, so it also hosts the
study's Use cases and Limitations of the data. Step 4 answers HOW attacks happened; this file does not repeat it.

Everything here is a corpus keyword label or a read of another project's artifacts; nothing is coded from reports yet.
llm() is where hand codes replace the corpus labels in the next phase.
Output: out/s05_techniques.md
"""
import ast, collections, json, re
from common import (load_full, load_rv, join_rv, load_prelabels, owasp_names, blind_agreement, source_class, text, write,
                    READ, OUT, EXT, CYCLE, CHANNELS)

S = json.load(open(OUT / "split.json")); C = load_full(); R = list(C.values())
rv = load_rv(); JR = join_rv(C, rv); J = JR["rows"]; PRE = load_prelabels()
NM = owasp_names(rv); RV2C, C2RV, RVN = NM["rv2corpus"], NM["corpus2rv"], NM["rv"]
POPS = ("ON-AI", "WITH-AI"); P = {p: [C[i] for i, s in S.items() if s["population"] == p] for p in POPS}
METH = json.load(open(OUT / "methodology.json"))      # step 4's rule outputs; the WITH-AI 'No entry fits' kinds are its attacker-objective rule
DEMO = ("research", "research-demonstrated", "red-team")
MIN_RECORDS = 30     # below this many corpus records a category is marked (n<30) and left out of the 'places' bullets
MARKER_SHARE = 0.9   # a code is a channel marker (‡) when it sits on this share of one channel's records, or of its own assignments
MIN_HAND = 2         # a proposed addition gets its own row from this many hand labels; MIN_BULLET its own place in the bullets and use cases
WIDE = 10            # a data-rank interval spanning this many places is 'wide' (limitations)
MIN_BULLET, TITLE = 5, 60
WLA, MIS = next(e for e, n in RVN.items() if n == "Weaponized LLM Abuse"), next(e for e, n in RVN.items() if n == "Misinformation")
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
def median(xs): xs = sorted(xs); return xs[len(xs) // 2] if xs else 0
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
    """The AST of one top-level assignment in a script, read (never run) — the corpus build script's seed table, step 4's rule list."""
    return next(n.value for n in ast.parse(path.read_text()).body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == name)
SEED = ast.literal_eval(src_assign(EXT / "corpus_merge_and_dedupe.py", "_VECTOR_TO_OWASP_LLM"))          # attack_vector -> OWASP LLM seed codes
# step 4's attacker-objective rule, (name, regex) in rule order, so the WITH-AI 'No entry fits' example can be the record matching most of its cue words
OBJ = [(t.elts[0].value, re.compile(t.elts[1].args[0].value, re.I)) for t in src_assign(OUT.parent / "s04_methodology.py", "OBJECTIVE").elts]
S4 = {k: m.group(1) for k, v in ast.literal_eval(src_assign(OUT.parent / "s04_methodology.py", "DIM_NAME")).items() if (m := re.search(r"\(([\d.]+)\)", v))}  # step 4's table numbers
VCI = vote_ci(); VR = {e: rv["ranks"][e]["vote_rank"] for e in rv["ranks"]}
def seed_share(rows):
    lab = [(r, c) for r in rows for c in llm(r)]; return sum(c in SEED.get(r.get("attack_vector") or "", []) for r, c in lab), len(lab)

# hand-labelled rows per population: (id, record, label list in rank-validation ids; [] = no entry fits)
GOLD = {p: [(i, C[i], J[i]["gold_labels"]) for i, s in S.items() if s["population"] == p and i in J and J[i]["gold_labels"] is not None] for p in POPS}
HUM = {p: collections.Counter(e for _, _, gl in GOLD[p] for e in gl) for p in POPS}
NONE = {p: [(i, r) for i, r, gl in GOLD[p] if gl == []] for p in POPS}
def note(i): return rv["gold"][J[i]["snapshot_id"]].get("notes")
def outcome(gl): return "no entry" if gl == [] else ("Misinformation" if MIS in gl else ("Weaponized LLM Abuse" if WLA in gl else "other entry"))
def tier_of(i): return (PRE.get(J[i]["snapshot_id"]) or {}).get("triage_tier")
KAPPA, KCI = rv["concordance"]["weighted_kappa_median"], rv["concordance"]["weighted_kappa_ci"]
def sg(x): return f"{x:.2f}".replace("-", "−")
cve_all = [r for r in R if source_class(r) == "cve/ghsa"]; sc_cve = sum("LLM04" in llm(r) for r in cve_all)
ENTRIES = sorted(rv["ranks"], key=lambda e: (VR[e], e)); TEN = [e for e in ENTRIES if e in RV2C]; ADDS = [e for e in ENTRIES if e not in RV2C]
GW, n_wi = GOLD["WITH-AI"], len(GOLD["WITH-AI"]); w_none = len(NONE["WITH-AI"]); n_on = len(P["ON-AI"]); ON = P["ON-AI"]
gold_ids = set(rv["gold"]); g_rec = sum(v["gold_labels"] is not None for v in J.values())
g_pop = collections.Counter(S[i]["population"] for i, v in J.items() if v["gold_labels"] is not None and i in S)   # where the hand-labelled records fall in step 2's split
quota = collections.Counter((PRE[i]["consensus"], PRE[i]["agreement"]) for i in gold_ids if i in PRE and PRE[i]["triage_tier"] != "disagree" and PRE[i]["consensus"] != "out-of-scope")
cap = {a: max(v for (c, aa), v in quota.items() if aa == a) for a in ("3-of-3", "2-of-3")}    # the per-entry quota, recovered as the largest cell
ALL_CH = {x: [r for r in R if source_class(r) == x] for x in CHANNELS}
def marker_why(c):
    tot = sum(c in llm(r) for r in R)
    for x, ch in ALL_CH.items():
        k = sum(c in llm(r) for r in ch)
        if k >= MARKER_SHARE * len(ch): return f"{ename(c)} on {pc(k, len(ch))}% of {x} records"
        if k >= MARKER_SHARE * tot: return f"{pc(k, tot)}% of {ename(c)} labels from {x}"
MARKER = {c: w for c in NM["corpus"] if (w := marker_why(c))}
# the rubric's requirement, quoted from the taxonomy files; and this study's reading of each 'No entry fits' kind (a recorded judgement, not a measurement)
RUB = {"pi": rub("LLM01_PromptInjection.md", "alters the model's behavior in ways the operator did not intend"),
       "mis": rub("LLM09_Misinformation.md", "trusted and acted upon"), "wla": rub("weaponized-llm-abuse.md", "cyberattacks against third-party targets")}
SUBSTANTIVE = "No concrete LLM vulnerability mechanism in incident text."
READING = {"ON-AI": "classifier evaluations (adversarial-input) are not attacks; misused decision tools (tool-abuse) name no adversary; jailbroken-model reports and non-LLM code bugs "
                    "fit nowhere; one-record vectors: agent-platform bugs and companion-bot harms with no stated LLM input",
           "WITH-AI": "deepfake fraud, political and defamatory deepfakes and abuse imagery from image or voice generators have no LLM mechanism; a tracker stub gives the adjudicator nothing to read"}
half = [e for e in TEN if VR[e] != int(VR[e])]   # a non-integer vote rank is a tie in the vote

# ---------------------------------------------------------------- opener
L = ["# Step 5 — Which attack categories stand out against the expert vote, and what the hand labels say", "",
     f"Generated by `s05_techniques.py` (`make s05`); do not edit by hand; inputs pinned in `external/PINS.json`. {READ} Limitations: Table 5.4.", "",
     f"Which OWASP LLM Top 10 categories stand out in each population against the OWASP community vote ({len(ENTRIES)} candidates ranked by respondents; the \"expert vote\" of the title), "
     f"and what do one person's hand labels say about them? Three sources: corpus categories, which are keyword labels; one person's hand labels on a quota sample "
     f"({len(GOLD['ON-AI'])} ON-AI and {n_wi} WITH-AI of the {g_rec:,} hand-labelled records that join; {g_pop['NONE']:,} are NONE, records whose step-2 rules find no adversary, "
     f"{g_pop['UNRESOLVED']} UNRESOLVED, {g_pop['BOTH']} BOTH), so no CI and no ranking; and rank-validation's vote with its 90% interval (its data rank and verdict: Table 1.15). "
     f"Step 4 answers how the attacks happened; names are rank-validation's, corpus code in brackets."]

# ---------------------------------------------------------------- Tables 5.1 / 5.2
def kinds_of(p):
    """'No entry fits' rows split into kinds: WITH-AI by step 4's attacker-objective rule (every rule value, in rule order, plus unstated),
    ON-AI by the corpus attack vector (one-record vectors pooled). Returns {kind: (rows, regex or None)}."""
    rows = NONE[p]; k = collections.defaultdict(list)
    if p == "WITH-AI":
        for i, r in rows: k[METH[i]["objective"]].append((i, r))
        return {**{o: (k[o], rx) for o, rx in OBJ}, "no objective stated": (k["unstated"], None)}
    for i, r in rows: k[r.get("attack_vector") or "no vector"].append((i, r))
    ones = sorted(v for v, rs in k.items() if len(rs) == 1); out = {v: (rs, None) for v, rs in k.items() if len(rs) > 1}
    if ones: out[f"{len(ones)} one-record vectors ({', '.join(ones)})"] = ([x for v in ones for x in k[v]], None)
    return out
def example(rs, rx):
    """One example per kind: a record of the kind's dominant form (stub or full description) matching the most of the rule's cue words, lowest id on ties."""
    maj = 2 * sum(stub(r) for _, r in rs) >= len(rs); pool = [x for x in rs if stub(x[1]) == maj] or rs
    cues = lambda r: sorted({m.group(0).lower() for m in rx.finditer(text(r))}) if rx else []
    i, r = min(pool, key=lambda x: (-len(cues(x[1])), x[0])); w = cues(r)
    return f"e.g. {i}" + (f" (matched '{w[0]}')" if w else "") + f": {cut(r['title'])}"
def kind_label(kd, rs, show): st = sum(stub(r) for _, r in rs); return kd + (f" ({st} of {len(rs)} are tracker stubs)" if st and show else "")

def category_table(p, num):
    rows, n = P[p], len(P[p]); G = GOLD[p]; ng = len(G); on = p == "ON-AI"; hum = HUM[p]; none = NONE[p]; nn = len(none); st_all = sum(stub(r) for _, r in none)
    cnt = collections.Counter(c for r in rows for c in set(llm(r))); crank = ranks(cnt)
    def carries(e, c=None):       # of the records the person filed under e, how many the corpus also codes with the same category
        filed = [r for _, r, gl in G if e in gl]
        if c: return sum(c in llm(r) for r in filed), len(filed)
        cc = collections.Counter(x for r in filed for x in llm(r)).most_common()
        if not cc: return "no code; the corpus files them nowhere"
        keep = [(x, v) for x, v in cc if v >= cc[min(1, len(cc) - 1)][1]]       # the two most frequent codes, every code tied with the second kept
        return "no code; filed as " + ", ".join(f"{ename(x)} {v}" for x, v in keep) + (" (tied)" if len(keep) > 2 else "")
    adds = [e for e in ADDS if hum[e] >= MIN_HAND]; pooled = [e for e in ADDS if e not in adds]
    places = {e: VR[e] - crank[RV2C[e]] for e in TEN if RV2C[e] in crank}
    big = [e for e in places if cnt[RV2C[e]] >= MIN_RECORDS]
    top, bot = max(places[e] for e in big), min(places[e] for e in big)
    his = [e for e in big if places[e] == top]; los = [e for e in big if places[e] == bot]; hi = his[0]
    nm = lambda es: andlist(ename(RV2C[e]) for e in es)
    dash = "— | " * (1 if on else 0)
    cols = ["category [corpus code]", "vote rank (90% interval)", "corpus records n (%)", "corpus rank", "places above the vote"] + (["demonstrated, % of the code's records"] if on else []) \
           + [f"hand labels (of {ng})", "corpus also carries the label"]
    kinds = {kd: v for kd, v in kinds_of(p).items() if v[0]}; empty = [kd for kd, v in kinds_of(p).items() if not v[0]]
    if on:
        desc = (f"*Corpus rank* orders the ten categories by {p} records carrying the code; *places above the vote* = vote rank − corpus rank ({signed(places[hi])}: the corpus ranks "
                f"{ename(RV2C[hi])} {abs(places[hi]):g} places higher than the vote); a vote rank of {VR[half[0]]:g} is a tie for {int(VR[half[0]])}th and {int(VR[half[0]]) + 1}th; "
                f"(n<30) = under {MIN_RECORDS} corpus records, kept out of the bullets; *demonstrated* = research, research-demonstrated or red-team (glossary); "
                f"*corpus also carries the label* = of the records the person filed under this entry, how many the corpus also codes with it; for a proposed addition, the codes "
                f"those records carry (a record can carry several, so counts can exceed the hand labels); ‡ = channel marker, a code on {MARKER_SHARE:.0%}+ of one channel's records "
                f"or drawn {MARKER_SHARE:.0%}+ from one channel ({'; '.join(MARKER[c] for c in sorted(MARKER))}), so agreement on it is agreement with the feed. "
                f"↳ rows split *No entry fits* by corpus attack vector (one-record vectors pooled), one lowest-id example each; {st_all} of the {nn} are tracker stubs.")
    else:
        wd = sum(r["category"] in DEMO for r in rows)
        desc = (f"The OWASP list scopes LLM applications, so records where the AI is the attacker's instrument are expected to fall outside it. Columns as in Table 5.1 without "
                f"*demonstrated* ({p} has {wd} demonstration record{'s' * (wd != 1)}). The ↳ rows split *No entry fits* by step 4's attacker-objective rule, a keyword rule over title, "
                f"description and affected text, every value of the rule listed ({andlist(empty) + ': none here' if empty else 'all present'}); the example is the record of the kind's "
                f"dominant form (tracker stub or full text) matching the most cue words, with the word matched, so it shows what the rule saw rather than a typical case. "
                f"{st_all} of the {nn} are tracker stubs, a description that is only an OECD, AIID or AIAAIC pointer (step 4), so the rule read their titles alone.")
    L.extend(head(num, f"{p}: {nm(his)} sits {signed(top)} places above its vote rank, {nm(los)} {signed(bot)}; {len(adds)} proposed additions with {MIN_HAND}+ hand labels "
                       f"and no corpus code, {len(pooled)} more pooled; {nn} of {ng} hand-labelled records fit no entry", f"n = {n:,} {p} records; {ng} hand-labelled", desc, cols))
    for e in TEN:
        c = RV2C[e]; lo_, hi_ = VCI[e]; a, b = carries(e, c)
        demo = [pc(sum(r["category"] in DEMO for r in rows if c in llm(r)), cnt[c], 0) if cnt[c] else "—"] if on else []
        L.append(f"| {code(c)}{'‡' if c in MARKER else ''} | {VR[e]:g} ({lo_:g}–{hi_:g}) | {npc(cnt[c], n)}{' (n<30)' if cnt[c] < MIN_RECORDS else ''} | {crank.get(c, '—')} | "
                 f"{signed(places[e]) if e in places else '—'} | " + "".join(f"{d} | " for d in demo) + f"{hum[e]} | {f'{a} of {b}' if b else '—'} |")
    for e in adds:
        lo_, hi_ = VCI[e]
        L.append(f"| {RVN[e]} [proposed] | {VR[e]:g} ({lo_:g}–{hi_:g}) | — | — | — | {dash}{hum[e]} | {carries(e)} |")
    L.append(f"| *{len(pooled)} other proposed additions* | {min(VR[e] for e in pooled):g}–{max(VR[e] for e in pooled):g} | — | — | — | {dash}{sum(hum[e] for e in pooled)} | "
             f"{', '.join(f'{RVN[e]} {hum[e]}' for e in pooled if hum[e]) or 'none'}; {sum(not hum[e] for e in pooled)} with none |")
    L.append(f"| *No entry fits* | — | — | — | — | {dash}{nn} ({pc(nn, ng)}%) | — |")
    for kd, (rs, rx) in sorted(kinds.items(), key=lambda x: (-len(x[1][0]), x[0])):
        L.append(f"| ↳ {kind_label(kd, rs, not on)} — {example(rs, rx)} | — | — | — | — | {dash}{len(rs)} | — |")
    # what stands out
    def why(e):
        c = RV2C[e]; d = sum(r["category"] in DEMO for r in rows if c in llm(r))
        return " (channel marker)" if c in MARKER else (f" (demonstrated on {pc(d, cnt[c], 0)}% of its records)" if on else "")
    bullets = [f"- Largest moves among categories with {MIN_RECORDS}+ corpus records: {nm(his)} {signed(top)}{why(hi)}; {nm(los)} {signed(bot)}" + (" (tied)" if len(los) > 1 else "") + "."]
    car = {e: carries(e, RV2C[e]) for e in TEN if hum[e] >= MIN_BULLET and RV2C[e] not in MARKER}
    if car:
        b_hi = max(car, key=lambda e: (car[e][0] / car[e][1], hum[e])); b_lo = min(car, key=lambda e: (car[e][0] / car[e][1], -hum[e]))
        bullets.append(f"- Hand labels the corpus also carries, outside the channel markers and with {MIN_BULLET}+ labels: {ename(RV2C[b_hi])} {car[b_hi][0]} of {car[b_hi][1]}"
                       + (f"; {ename(RV2C[b_lo])} only {car[b_lo][0]} of {car[b_lo][1]}." if b_lo != b_hi else "."))
    big_adds = sorted((e for e in ADDS if hum[e] >= MIN_BULLET), key=lambda e: (-hum[e], VR[e]))
    if big_adds: bullets.append(f"- Proposed additions with {MIN_BULLET}+ hand labels and no corpus code (the code the corpus filed most of them under): " + "; ".join(f"{RVN[e]} {hum[e]} ({carries(e).split('filed as ')[1].split(',')[0]})" for e in big_adds) + ".")
    top_k = max(kinds.items(), key=lambda x: len(x[1][0]))
    bullets.append(f"- No entry fits: {nn} of {ng} hand-labelled records ({pc(nn, ng)}%), {st_all} of them tracker stubs; the largest kind is {top_k[0]} ({len(top_k[1][0])}).")
    boiler = sum(note(i) != SUBSTANTIVE for i, _ in none); subst = sum(note(i) == SUBSTANTIVE for i, _ in none)
    L.extend(["", "What stands out:", ""] + bullets + ["",
              "*Why the person placed these nowhere.* " + (f"The rubric wants an LLM mechanism: input that \"{RUB['pi']}\" (Prompt Injection), output "
              f"\"{RUB['mis']}\" (Misinformation), or \"{RUB['wla']}\" (Weaponized LLM Abuse). " if on else "The rubric's requirement is quoted under Table 5.1. ")
              + f"Notes: boilerplate or empty on {boiler} of {nn}; the one substantive, \"{SUBSTANTIVE}\", on {subst}. Reading: {READING[p]}."])
    return cnt, crank, places, carries
cnt_on, crank_on, places_on, carries_on = category_table("ON-AI", "5.1")
cnt_wi, crank_wi, places_wi, carries_wi = category_table("WITH-AI", "5.2")
L += ["", f"Neither table is a prevalence ranking or a corrected Top 10: corpus labels are keyword rules that mark the channel more than the content ({ename('LLM04')} sits on "
      f"{pc(sc_cve, len(cve_all))}% of CVE/GHSA records), the hand-labelled rows are a quota sample, and the vote is {len(ENTRIES)} candidates ranked by respondents."]

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
          "By the three LLM pre-labellers' tier; the disagree tier was taken in full, the others by quota; kinds in Tables 5.1 and 5.2.",
          ["population", "pre-label tier", "hand-labelled", "no entry fits n (%)", RVN[MIS], RVN[WLA], "other entry"])
for p in POPS:
    for t, tn in TIERS:
        o = collections.Counter(outcome(gl) for i, _, gl in GOLD[p] if tier_of(i) == t); g = sum(o.values())
        L.append(f"| {p} | {tn} | {g} | {npc(o['no entry'], g)} | {o['Misinformation']} | {o['Weaponized LLM Abuse']} | {o['other entry']} |")
no_tier = {p: sum(not tier_of(i) for i, _, _ in GOLD[p]) for p in POPS}
if any(no_tier.values()): L += ["", f"Rows without a pre-label tier are left out: {', '.join(f'{p} {v}' for p, v in no_tier.items() if v)}."]

# ---------------------------------------------------------------- Use cases
ioh, mcp, exa = "LLM10", next(e for e, n in RVN.items() if n.startswith("MCP")), next(e for e, n in RVN.items() if n == "Excessive Agency")
demo_on = {c: sum(r["category"] in DEMO for r in ON if c in llm(r)) / v for c, v in cnt_on.items() if v >= MIN_RECORDS}
lo_d = min(demo_on, key=lambda c: (demo_on[c], c))
hum_on, hum_wi = HUM["ON-AI"], HUM["WITH-AI"]
top_hand = max(TEN, key=lambda e: (hum_on[e], -VR[e]))
best = max((e for e in TEN if hum_on[e] >= MIN_BULLET and RV2C[e] not in MARKER), key=lambda e: (carries_on(e, RV2C[e])[0] / carries_on(e, RV2C[e])[1], hum_on[e]))
def cs(e, f=carries_on): a, b = f(e, RV2C[e]); return f"{a} of {b}"
missing = [RVN[e] for e in ADDS if max(hum_on[e], hum_wi[e]) >= MIN_BULLET]
L += ["", "## Use cases", "",
      f"- *Deployers.* ON-AI: {ename(ioh)} {signed(places_on[C2RV[ioh]])} places (corpus-coded on {cs(C2RV[ioh])}); {RVN[mcp]} {hum_on[mcp]} hand labels, "
      f"no code (filed as {carries_on(mcp).split('filed as ')[1].split(',')[0]}); {RVN[exa]} corpus-coded on {cs(exa)}.",
      f"- *Researchers.* {RVN[top_hand]}: most-used hand label ({hum_on[top_hand]}), corpus-coded on {cs(top_hand)}; {RVN[best]}: best carried outside channel markers ({cs(best)}); "
      f"{ename(lo_d)}: realized, rarely demonstrated ({100*demo_on[lo_d]:.0f}%).",
      f"- *Framework authors.* {w_none} of {n_wi} WITH-AI hand labels fit no entry and {RVN[WLA]} ({hum_wi[WLA]} hand labels) has no code: deepfake fraud is outside the list's LLM-mechanism scope.",
      f"- *Database maintainers.* {andlist(missing)} need a code ({MIN_BULLET}+ hand labels).", "",
      "**Not supported:** prevalence; a corrected Top 10; attack chains; mitigations, their adoption or efficacy; trends; attribution or exploitation status; technique-level statements about how attackers operated."]

# ---------------------------------------------------------------- Limitations of the data (Table 5.4)
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
prec = {p: collections.Counter(len(str(r["date"])) for r in P[p]) for p in POPS}
stubs_wi = [r for r in P["WITH-AI"] if r.get("description_provenance") == "original"]
cwe_pi = sum("CWE-1427" in (r.get("cwe_ids") or []) for r in R)
pi_cve = [r for r in ON if r.get("attack_vector") == "prompt-injection" and r.get("cve_ids")]
mit_f = {p: sum(bool(r.get("mitigations")) for r in P[p]) for p in POPS}
sc_rv = C2RV["LLM04"]; on_ch = {x: [r for r in ON if source_class(r) == x] for x in CHANNELS}
unst = {d: sum(METH[i].get(d) == "unstated" for i in S if i in METH and S[i]["population"] == pp) for pp, d in (("ON-AI", "entry_point"), ("WITH-AI", "objective"))}
STEP = [  # this step's own tables
    ("**Labels are rule outputs.** Tables 5.1 and 5.2 rank keyword rules, not observed techniques.",
     f"the corpus derives the OWASP code from the attack_vector field for {pc(*seed_share(R))}% of codes.", "5.1, 5.2"),
    (f"**{ename('LLM04')} marks the CVE channel.** Its ON-AI corpus rank {crank_on['LLM04']} arrives with the feed, whatever the attack vector.",
     f"{sc_cve:,} of {len(cve_all):,} CVE/GHSA records ({pc(sc_cve, len(cve_all))}%) carry the code; within ON-AI {pc(sum('LLM04' in llm(r) for r in on_ch['cve/ghsa']), len(on_ch['cve/ghsa']))}% of cve/ghsa vs "
     f"{pc(sum('LLM04' in llm(r) for r in on_ch['harm-db']), len(on_ch['harm-db']))}% of harm-db.", "1.10, 5.1"),
    ("**Hand labels: one coder, a quota sample.** Never a ranking or a prevalence.",
     f"{len(gold_ids):,} rows: up to {cap['3-of-3']} + {cap['2-of-3']} per consensus entry ({tier_g['entry']}), all {tier_g['disagree']} disagree rows, {tier_g['oos']} no-entry-majority rows; "
     f"the coder's label before seeing the pre-labels equals the final label on {pc(blind_eq, len(gold_ids))}%.", "1.14, 5.1, 5.2"),
    (f"**No-entry shares describe the sample.** The {pc(w_none, n_wi, 0)}% is not the share of WITH-AI records that fit no entry.",
     f"{none_t['disagree'][0]} of {w_none} no-entry rows are disagree rows, a tier taken in full ({taken_t['disagree'][0]} of {taken_t['disagree'][1]}).", "5.3"),
    ("**Weak vote–data concordance.** Rank-validation's whole-snapshot finding, used here only to set expectations.",
     f"weighted κ {KAPPA:.2f} ({sg(KCI[0])} to {sg(KCI[1])}) over {rv['concordance']['measurable_count']} of {rv['concordance']['total_count']} entries; {wide} of {len(rv['ranks'])} data-rank intervals span {WIDE}+ places.", "1.15"),
    ("**OWASP numbering mismatch.** Every join is by name and every table prints names.",
     f"{diff_codes} of ten entries carry different codes ({ename('LLM04')} is corpus [LLM04], rank-validation {sc_rv}).", "1.0"),
]
STUDY = [  # the study's shared limitations, hosted here because this file runs last
    ("**Channel confounding.** Any pooled ON/WITH comparison compares channels.",
     f"cve/ghsa {frame['cve/ghsa']['ON-AI']:,} of {sum(frame['cve/ghsa'].values()):,} frame records are ON-AI; harm-db {frame['harm-db']['WITH-AI']:,} of {sum(frame['harm-db'].values()):,} are WITH-AI.", "2.2, 1.6, 1.7, 2.10"),
    ("**The split is rule-based.** Error rates are unmeasured.",
     f"{wv_silent:,} of {len(wv):,} vector-only WITH-AI rows contain no adversary word; {sum(source_class(r) == 'cve/ghsa' for r in P['WITH-AI'])} WITH-AI rows are CVE/GHSA; "
     f"{hum_on[WLA]} ON-AI hand labels are {RVN[WLA]}, {hum_wi[sc_rv]} WITH-AI {ename('LLM04')}.", "2.5, 5.1, 5.2"),
    ("**Join losses and merged duplicates.** Hand labels cover the pre-May-2026 part of each population.",
     f"{g_unres} of {len(gold_ids):,} hand-labelled ids unresolved; {g_land:,} land on {g_rec:,} records ({multi_dis} with disagreeing copies); {pc(*cover['ON-AI'])}% of ON-AI and "
     f"{pc(*cover['WITH-AI'])}% of WITH-AI records existed in the snapshot rank-validation labelled ({len(GOLD['ON-AI'])} and {n_wi} of them hand-labelled).", "1.13"),
    ("**Six limitations stated in full in steps 1, 2 and 4**: record year is ingestion (no trend); date precision; short, partly stub descriptions; "
     "CVE records coded as conventional weaknesses; step 4 unstated shares; exploitation and housekeeping fields empty.",
     f"{sum(r['year'] == 2026 for r in y19):,} of {len(y19):,} records from 2019 on carry 2026; ON-AI {pc(prec['ON-AI'][7], n_on)}% month-only; median description {med(R)} characters, "
     f"{len(stubs_wi)} WITH-AI stubs ({pc(len(stubs_wi), len(P['WITH-AI']))}%); CWE-1427 on {cwe_pi} records vs {len(pi_cve)} prompt-injection CVEs; "
     f"entry point unstated {pc(unst['entry_point'], n_on)}%, objective {pc(unst['objective'], len(P['WITH-AI']))}%; `mitigations` filled on {mit_f['ON-AI']} ON-AI records.",
     f"1.5, 1.7, {S4.get('entry_point', '4')}, {S4.get('objective', '4')}, step 4's fields table"),
]
LIM = STEP + STUDY
L += ["", "## Limitations of the data", "",
      f"genai_incidents is an index of other trackers in which every label is a rule's output, so this study finds and stratifies incidents with it, never measures them; "
      f"rows 1–{len(STEP)} bound this step's tables, rows {len(STEP) + 1}–{len(LIM)} the study as a whole (this file runs last; row {len(LIM)} bundles six stated in full in steps 1, 2 and 4)."]
L += head("5.4", f"{len(LIM)} limitation rows: {len(STEP)} on this step's tables, {len(STUDY)} shared by every step", f"n = {len(R):,} corpus records",
          None, ["#", "limitation", "the number that bounds it", "tables"])
L += [f"| {i} | {a} | {b} | {c} |" for i, (a, b, c) in enumerate(LIM, 1)]
write("s05_techniques.md", L)
