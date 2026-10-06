#!/usr/bin/env python3
"""s05_techniques.py — Step 5. OWASP categories per population beside the community vote and one person's hand labels,
then the corpus's OWASP -> ATLAS lookup followed to ATLAS mitigations and gaps (after Hamer et al., "Closing the Chain",
arXiv:2503.12192). Runs last, so it also hosts the study's single Use cases and Limitations of the data sections.

Everything here is a corpus keyword label or a read of another project's artifacts; nothing is coded from reports yet.
llm(), asi() and techs() are where hand codes replace the corpus labels in the next phase.
Output: out/s05_techniques.md
"""
import ast, collections, json, re
from common import (load_full, load_atlas, load_rv, join_rv, load_prelabels, owasp_names, blind_agreement, source_class, text, table, write, boot_ci,
                    READ, OUT, EXT, CYCLE, CHANNELS)

S = json.load(open(OUT / "split.json")); C = load_full(); R = list(C.values()); A = load_atlas(); REF = json.load(open(EXT / "mitre_atlas.json"))
PINS = json.load(open(EXT / "PINS.json")); rv = load_rv(); JR = join_rv(C, rv); J = JR["rows"]; PRE = load_prelabels()
NM = owasp_names(rv); NAME = {**NM["corpus"], **NM["asi"]}; RV2C, C2RV, RVN = NM["rv2corpus"], NM["corpus2rv"], NM["rv"]
POPS = ("ON-AI", "WITH-AI"); P = {p: [C[i] for i, s in S.items() if s["population"] == p] for p in POPS}
DEMO = ("research", "research-demonstrated", "red-team")
MIN_RECORDS = 30     # below this many corpus records a category is 'too few records' and a channel gets no within-channel rank
MARKER_SHARE = 0.9   # a code is a channel marker when it sits on this share of one channel's records, or of its own assignments
FLOOR = 20           # profile rows below this many records show counts only
SMALL = 10           # hand-labelled agreement cells below this many rows show counts only
def rtype(r): return "demonstrated" if r["category"] in DEMO else ("threat report" if r["category"] == "threat-report" else "realized / disclosed")
# entries rank-validation declared unobservable in this corpus and left out of its ranking (glossary: frame-blind); by name, never by number
FRAME_BLIND = {e for e, n in RVN.items() if n in ("Data and Model Poisoning", "Vector and Embedding Weaknesses", "Unbounded Consumption")}
WLA, MIS = next(e for e, n in RVN.items() if n == "Weaponized LLM Abuse"), next(e for e, n in RVN.items() if n == "Misinformation")

def llm(r): return r.get("owasp_llm") or []              # <- hand codes replace these three after the coding phase
def asi(r): return r.get("owasp_asi") or []
def techs(r): return r.get("mitre_atlas") or []
def code(c): return f"{c} {NAME[c]}"
def parent(t): return t.rsplit(".", 1)[0] if t.count(".") == 2 else t
def tname(t): return (A["techniques"].get(t) or REF["techniques"].get(t) or {}).get("name", "?")
def label(t): return f"{t} {tname(t)}"
def tactics(t): return [REF["tactics"][x]["name"] for x in (REF["techniques"].get(t) or {}).get("tactics") or (REF["techniques"].get(parent(t)) or {}).get("tactics") or []]
def mits(t): return A["mitigates"].get(t, set()) | A["mitigates"].get(parent(t), set())    # a sub-technique inherits its parent's mitigations
def attack_ref(t): return (A["techniques"].get(t) or {}).get("attack_ref") or (A["techniques"].get(parent(t)) or {}).get("attack_ref")    # own, else the parent's (as mits)
def pc(a, b, d=1): return f"{100*a/b:.{d}f}" if b else "—"
def npc(a, b): return f"{a:,} ({pc(a, b)}%)"
def ranks(counter): return {k: 1 + sum(w > v for w in counter.values()) for k, v in counter.items() if v}    # ties share a rank
def mc(counter, k=None): return sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))[:k]    # most_common with a deterministic tie-break
def lead(counter, n, small=False):
    """The most frequent value(s) with their share, every value tied at the top; a count instead of a share when small."""
    if not counter: return "—"
    top = max(counter.values()); ks = sorted(k for k, v in counter.items() if v == top)
    return " / ".join(ks) + (f" {top}" if small else f" {100*top/n:.0f}%")
def gname(gl): return RVN[gl[0]] if gl else "no entry"    # a hand label list as a name
def ordn(x): return (f"{int(x)}{'th' if 10 <= int(x) % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(int(x) % 10, 'th')}") if float(x).is_integer() else f"{x:g}th"
def median(xs): xs = sorted(xs); return xs[len(xs) // 2] if xs else 0
def join_names(xs): return ", ".join(xs[:-1]) + f" and {xs[-1]}" if len(xs) > 1 else "".join(xs)
def uniq(xs): return list(dict.fromkeys(xs))
def chan(rows): return {x: [r for r in rows if source_class(r) == x] for x in CHANNELS}

def vote_ci():
    """Vote-rank 90% intervals from rank-validation's rank_comparison_report.md (load_rv parses the line but keeps only the point rank)."""
    pat = re.compile(r"^\|\s*([A-Z0-9-]+)\s*\|[^|]*\|\s*([\d.]+) \(([\d.]+)[–-]([\d.]+)\)")
    return {m.group(1): (float(m.group(3)), float(m.group(4))) for l in open(CYCLE / "results/rank_comparison_report.md") if (m := pat.match(l.strip()))}
VCI = vote_ci()
FLAGS = {f["entry_id"]: f for f in rv["concordance"]["flags"]}

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
    """(assignments equal to the code seeded from the record's attack_vector, all OWASP LLM code assignments)."""
    lab = [(r, c) for r in rows for c in llm(r)]; return sum(c in SEED.get(r.get("attack_vector") or "", []) for r, c in lab), len(lab)

# hand-labelled rows per population: (id, record, label list in rank-validation ids; [] = no entry fits)
GOLD = {p: [(i, C[i], J[i]["gold_labels"]) for i, s in S.items() if s["population"] == p and i in J and J[i]["gold_labels"] is not None] for p in POPS}
def hand_counts(G): return collections.Counter(e for _, _, gl in G for e in gl), sum(gl == [] for _, _, gl in G)
def outcome(gl): return "no entry" if gl == [] else ("Misinformation" if MIS in gl else ("Weaponized LLM Abuse" if WLA in gl else "other entry"))
def outcome_cells(G):
    o = collections.Counter(outcome(gl) for _, _, gl in G); n = len(G)
    return f"{o['no entry']} ({pc(o['no entry'], n)}%) | {o['Misinformation']} | {o['Weaponized LLM Abuse']} | {o['other entry']}"
KAPPA, KCI = rv["concordance"]["weighted_kappa_median"], rv["concordance"]["weighted_kappa_ci"]
def sg(x): return f"{x:.2f}".replace("-", "−")
cve_all = [r for r in R if source_class(r) == "cve/ghsa"]; sc_cve = sum("LLM04" in llm(r) for r in cve_all)
METH = json.load(open(OUT / "methodology.json")) if (OUT / "methodology.json").exists() else None

# ---------------------------------------------------------------- opener
derived = {p: pc(sum(len(set(techs(r)) & backfill(r)) for r in P[p]), sum(len(set(techs(r))) for r in P[p])) for p in POPS}
n_both = sum(s["population"] == "BOTH" for s in S.values())
L = ["# Step 5 — OWASP categories per population, where a human reader and the community vote disagree with the corpus, and the ATLAS mitigations the labels map to (draft before hand-coding)", "",
     f"Generated by `s05_techniques.py` (`make s05`); do not edit by hand. {READ}", "",
     f"The design follows Hamer et al., *Closing the Chain* (arXiv:2503.12192): collect what attackers did, map it to the framework tasks that mitigate it, "
     f"rank the tasks, and list what the framework leaves uncovered. Here the rows are OWASP LLM Top 10 (2026) categories, which are kinds of risk, not "
     f"techniques: they say what a record was filed under, not how the attacker operated. The corpus assigns them by keyword rules and then derives most of "
     f"its ATLAS technique labels from them with a fixed lookup ({derived['ON-AI']}% of ATLAS labels on ON-AI records and {derived['WITH-AI']}% on WITH-AI "
     f"records are what that lookup produces from the record's own OWASP codes), so the categories are the layer everything else rests on. The {n_both} BOTH "
     f"records are excluded. WITH-AI leaves after Table 5.7: neither OWASP nor ATLAS is written for the case where the AI is the attacker's instrument. "
     f"The technique → mitigation links are MITRE's own, from ATLAS {PINS['atlas_release']}; nothing is mapped by a model. Names: Tables 5.1, 5.2, 5.4 and 5.5 use rank-validation's entry names (Table 1.0); Tables 5.3 and 5.6–5.9 use the corpus's."]

# ---------------------------------------------------------------- Tables 5.1 / 5.2
L += ["", "## Which categories does each population carry, and where do a human reader and the vote disagree with the corpus?"]
ENTRIES = sorted(rv["ranks"], key=lambda e: (rv["ranks"][e]["vote_rank"], e))
DIRECTION = {"votes-over-lambda": "vote above data rank", "lambda-over-votes": "data rank above vote", "concordant": "concordant"}
def verdict(e):
    k = rv["ranks"][e]; out = f"{DIRECTION.get(k['direction'], k['direction'])}, {k['action']}"
    if e in FRAME_BLIND: out += "; frame-blind"
    if e in FLAGS: out += f"; flagged P = {FLAGS[e]['probability']:.2f} ({FLAGS[e]['direction'].replace('_', ' ')})"
    return out
# channel marker: in the whole corpus the code sits on >= 90% of one channel's records, or >= 90% of its assignments come from one channel
ALL_CH = chan(R)
MARKER = {c for c in NM["corpus"] if any(sum(c in llm(r) for r in ch) >= MARKER_SHARE * len(ch) for ch in ALL_CH.values())
          or any(sum(c in llm(r) for r in ch) >= MARKER_SHARE * sum(c in llm(r) for r in R) for ch in ALL_CH.values())}
def flag(e, c, cnt, crank, vr):
    if c is None: return "no corpus label"
    if cnt[c] < MIN_RECORDS: return "too few records"
    f = "corpus above vote" if vr - crank[c] >= 3 else ("vote above corpus" if crank[c] - vr >= 3 else "agree")
    return f + (" (channel marker)" if c in MARKER else "")

def category_table(p, num, title):
    rows, n = P[p], len(P[p]); G = GOLD[p]; ng = len(G)
    cnt = collections.Counter(c for r in rows for c in set(llm(r))); crank = ranks(cnt); hum, none = hand_counts(G)
    by_ch = chan(rows); shown = [x for x in CHANNELS if len(by_ch[x]) >= MIN_RECORDS]; hidden = [x for x in CHANNELS if x not in shown]
    chrank = {x: ranks(collections.Counter(c for r in by_ch[x] for c in set(llm(r)))) for x in shown}
    k = [len(set(llm(r))) for r in rows if llm(r)]; per = sum(k) / len(k)
    dd = [(i, J[i]["gold_all"], gl) for i, _, gl in G if len({tuple(g) for g in J[i]["gold_all"]}) > 1]    # merged duplicates whose copies were labelled differently
    L.extend(["", f"**Table {num}. {title}** (n = {n:,} {p} records; {ng} of them hand-labelled)", "",
              f"Each row compares the community vote ({len(ENTRIES)} candidate entries) with where the corpus's keyword labelling places the category in this population, "
              f"overall and within each disclosure channel, beside what one person who hand-labelled a non-random subset of the same records decided. The flag is a rule on the corpus and vote ranks "
              f"alone; the two hand-labelled columns show where the labellings disagree and how often the person kept the corpus's label"
              + (f" (within-channel ranks need {MIN_RECORDS} records; {', '.join(f'{x} has {len(by_ch[x])}' for x in hidden)} and is left out)" if hidden else "") + ".", "",
              f"| category (corpus code / rank-validation id) | vote rank (90% interval) | corpus records n (%; 95% CI) | corpus rank | " + "".join(f"rank in {x} | " for x in shown)
              + f"hand-labelled records the person filed here (of {ng}) | person kept the corpus label: agree / rows carrying it (%) | rank-validation's verdict | this study's flag |",
              "|---|---|---|---|" + "---|" * len(shown) + "---|---|---|---|"])
    for e in ENTRIES:
        c = RV2C.get(e); vr = rv["ranks"][e]["vote_rank"]; lo, hi = VCI[e]
        name = f"{RVN[e]} (corpus {c} / rv {e})" if c else f"{RVN[e]} (rv {e}; proposed addition)"
        carry = [gl for _, r, gl in G if c and c in llm(r)]; agree = sum(e in gl for gl in carry)
        kept = "—" if not c else (f"{agree} / {len(carry)} ({pc(agree, len(carry))}%)" if len(carry) >= SMALL else f"{agree} / {len(carry)}")
        if c and cnt[c]: _, blo, bhi = boot_ci(rows, lambda r, c=c: c in llm(r)); corp = f"{cnt[c]:,} ({pc(cnt[c], n)}%; {100*blo:.1f}–{100*bhi:.1f})"
        elif c: corp = "0"
        else: corp = "—"
        L.append(f"| {name} | {vr:g} ({lo:g}–{hi:g}) | {corp} | {crank.get(c, '—') if c else '—'} | " + "".join(f"{chrank[x].get(c, '—') if c else '—'} | " for x in shown)
                 + f"{npc(hum[e], ng)} | {kept} | {verdict(e)} | {flag(e, c, cnt, crank, vr)} |")
    L.append(f"| *No entry fits* | — | — | — | " + "— | " * len(shown) + f"{npc(none, ng)} | — | — | — |")
    L.extend(["", f"Flag rule: `corpus above vote` when the vote rank exceeds the corpus rank by 3 or more places, `vote above corpus` for the reverse, `agree` "
              f"otherwise, `too few records` below {MIN_RECORDS} corpus records; `(channel marker)` is appended when, in the whole corpus, the code sits on {100*MARKER_SHARE:.0f}% or more of one "
              f"channel's records or {100*MARKER_SHARE:.0f}% or more of its assignments come from one channel ({', '.join(NAME[c] for c in sorted(MARKER))}). `frame-blind` in the verdict column is an entry rank-validation declared unobservable "
              f"in this corpus and left out of its ranking. "
              f"{n - len(k):,} {p} records carry no OWASP LLM code and the rest carry {per:.1f} on average.", "",
              (f"{len(dd)} of the {ng} hand-labelled {p} records are merged duplicates whose snapshot copies received different labels "
               f"({'; '.join(f'{i}: {' vs '.join(uniq(gname(g) for g in ga))}, kept {gname(gl)}' for i, ga, gl in dd)}); the record's own label is kept where it has one, else the first copy in rank-validation's file order."
               if dd else f"No hand-labelled {p} record is a merged duplicate whose snapshot copies received different labels."), "",
              f"This is not a prevalence ranking, a corrected Top 10 or proof that the vote is wrong: the corpus column is a keyword labelling that marks the "
              f"disclosure channel more than the record's content (Supply Chain sits on {pc(sc_cve, len(cve_all))}% of all CVE/GHSA records), the hand-labelled "
              f"column counts a sample selected by what three LLM pre-labellers said (Table 1.14), the person gave one label where the corpus gives {per:.1f}, "
              f"and rank-validation's verdict is that project's finding (weighted κ {KAPPA:.2f}, interval {sg(KCI[0])} to {sg(KCI[1])}), used here only to set expectations."])
    return cnt, crank, hum, none

on_cnt = collections.Counter(c for r in P["ON-AI"] for c in set(llm(r))); top3 = [c for c, _ in mc(on_cnt, 3)]
t51 = (f"ON-AI: the corpus ranks {join_names([NAME[c] for c in top3])} first; the vote ranks them "
       f"{join_names([ordn(rv['ranks'][C2RV[c]]['vote_rank']) for c in top3])}")
cnt_on, crank_on, hum_on, none_on = category_table("ON-AI", "5.1", t51)
wi_cnt = collections.Counter(c for r in P["WITH-AI"] for c in set(llm(r))); w1 = mc(wi_cnt, 1)[0][0]; GW = GOLD["WITH-AI"]
w_carry = [gl for _, r, gl in GW if w1 in llm(r)]; w_agree = sum(C2RV[w1] in gl for gl in w_carry); w_none = sum(gl == [] for _, _, gl in GW)
t52 = (f"WITH-AI: the corpus files {pc(wi_cnt[w1], len(P['WITH-AI']), 0)}% under {NAME[w1]} (vote {ordn(rv['ranks'][C2RV[w1]]['vote_rank'])}); the person "
       f"confirms it on {w_agree} of {len(w_carry)} hand-labelled rows carrying it and files {pc(w_none, len(GW), 0)}% under no entry")
cnt_wi, crank_wi, hum_wi, none_wi = category_table("WITH-AI", "5.2", t52)

# ---------------------------------------------------------------- Table 5.3: what kind of record carries each category (ON-AI; WITH-AI is one sentence)
def profile_table(p, num, cnt):
    rows, n = P[p], len(P[p]); by_ch = chan(rows); floor = FLOOR
    def cell(h, c):
        m = len(h); ty = collections.Counter(rtype(r) for r in h); small = m < floor
        f = (lambda a, b: f"{a:,}") if small else (lambda a, b: npc(a, b))
        chs = " | ".join(("—" if small else pc(sum(c in llm(r) for r in by_ch[x]), len(by_ch[x]))) for x in CHANNELS)
        return (f"| {code(c)} | {m:,} | {f(ty['realized / disclosed'], m)} | {f(ty['demonstrated'], m)} | {ty['threat report']} | {chs} | "
                f"{'—' if small else pc(sum(bool(r.get('cve_ids') or r.get('cwe_ids')) for r in h), m, 0)} | "
                f"{lead(collections.Counter(r.get('attack_vector') or 'other' for r in h), m, small)} | {lead(collections.Counter(NAME[u] for r in h for u in set(llm(r)) if u != c), m, small)} |")
    demo = {c: sum(rtype(r) == "demonstrated" for r in rows if c in llm(r)) / v for c, v in cnt.items() if v >= floor}
    lo_c, hi_c = min(demo, key=demo.get), max(demo, key=demo.get)
    L.extend(["", f"**Table {num}. {p}: what kind of record carries each category: the demonstrated share runs from {NAME[lo_c]} {100*demo[lo_c]:.0f}% to {NAME[hi_c]} {100*demo[hi_c]:.0f}%** (n = {n:,} {p} records)", "",
              f"Per category, the corpus record type (realized/disclosed = real-world incident or vulnerability disclosure; demonstrated = research, "
              f"research-demonstrated or red-team), the share of each channel's {p} records carrying it, the share with a CVE or CWE id, and the most frequent "
              f"attack vector and co-assigned category (the top value or values, so not a distribution). Categories with fewer than {floor} records show counts only.", "",
              "| category | records | realized / disclosed n (%) | demonstrated n (%) | threat report (n) | % in cve/ghsa | % in harm-db | % in research/other | CVE or CWE (%) | top attack vector | most frequent co-label |",
              "|---|---|---|---|---|---|---|---|---|---|---|"])
    for c, m in mc(cnt): L.append(cell([r for r in rows if c in llm(r)], c))
    return demo
demo_on = profile_table("ON-AI", "5.3", cnt_on)
d_all = sum(rtype(r) == "demonstrated" for r in R); d_res = sum(rtype(r) == "demonstrated" for r in R if source_class(r) == "research/other")
lo_d = sorted(demo_on, key=lambda c: (demo_on[c], c))[:2]; hi_d = sorted(demo_on, key=lambda c: (-demo_on[c], c))[:3]
L += ["", f"'Demonstrated' is a source type as much as a finding: {d_res} of the corpus's {d_all} demonstrated records are research/other records. In ON-AI the "
      f"categories the index sees realized but rarely demonstrated are {join_names([NAME[c] for c in lo_d])} ({', '.join(f'{100*demo_on[c]:.0f}%' for c in lo_d)}); "
      f"the reverse holds for {join_names([NAME[c] for c in hi_d])} ({', '.join(f'{100*demo_on[c]:.0f}%' for c in hi_d)})."]
wi_rows = P["WITH-AI"]; df = {c: (sum((r.get("attack_vector") == "deepfake") for r in wi_rows if c in llm(r)), sum(bool(r.get("cve_ids") or r.get("cwe_ids")) for r in wi_rows if c in llm(r)), v) for c, v in cnt_wi.items() if v >= FLOOR}
sc_wi = [r for r in wi_rows if "LLM04" in llm(r)]
L += ["", f"Table 5.3 has no WITH-AI counterpart: every WITH-AI category with {FLOOR} or more records except Supply Chain is "
      f"{min(100*d/v for c, (d, x, v) in df.items() if c != 'LLM04'):.0f}–{max(100*d/v for c, (d, x, v) in df.items() if c != 'LLM04'):.0f}% deepfake records with "
      f"{min(100*x/v for c, (d, x, v) in df.items() if c != 'LLM04'):.0f}–{max(100*x/v for c, (d, x, v) in df.items() if c != 'LLM04'):.0f}% carrying a CVE or CWE; Supply Chain's "
      f"{pc(df['LLM04'][1], df['LLM04'][2], 0)}% CVE share is the {sum(source_class(r) == 'cve/ghsa' for r in sc_wi)} misplaced CVE rows of Table 2.5."]

# ---------------------------------------------------------------- Table 5.4: corpus code vs the person's label, record by record
def match_rows(G):
    """Per entry the person used: (entry, records, corpus codes include it, corpus codes are exactly it, most frequent corpus code where they differ)."""
    out = []
    for e, v in mc(collections.Counter(e for _, _, gl in G for e in gl)):
        c = RV2C.get(e); rs = [r for _, r, gl in G if e in gl]
        inc = sum(c in llm(r) for r in rs) if c else None; ex = sum(llm(r) == [c] for r in rs) if c else None
        diff = collections.Counter(NAME[x] for r in rs if not (c and c in llm(r)) for x in set(llm(r)))
        out.append((e, v, inc, ex, diff))
    return out
MATCH = {p: match_rows(GOLD[p]) for p in POPS}
t10 = {p: (sum(inc for e, v, inc, ex, d in MATCH[p] if inc is not None), sum(v for e, v, inc, ex, d in MATCH[p] if inc is not None)) for p in POPS}
L += ["", f"**Table 5.4. Corpus code vs the person's label, record by record: the corpus's codes include the person's entry on {t10['ON-AI'][0]} of {t10['ON-AI'][1]} ON-AI and "
      f"{t10['WITH-AI'][0]} of {t10['WITH-AI'][1]} WITH-AI rows the person filed under a Top 10 entry** (n = {len(GOLD['ON-AI'])} ON-AI and {len(GOLD['WITH-AI'])} WITH-AI hand-labelled records)", "",
      f"One row per entry the person chose, per population: how many of those records carry the same code among the corpus's codes, how many carry exactly that one code, and the corpus's "
      f"most frequent code on the records where it does not include the person's entry (for a proposed addition, which has no corpus code, on all of them); the last row is the records the person filed under no entry, with the corpus codes they carry. "
      f"The match is lenient because the corpus gives a record several codes and the person gave one; cells with fewer than {SMALL} records show counts only.", "",
      "| population | entry the person chose | hand-labelled records | corpus codes include it: n / records (%) | corpus codes are exactly it (n) | most frequent corpus code where they differ (n) |", "|---|---|---|---|---|---|"]
for p in POPS:
    for e, v, inc, ex, diff in MATCH[p]:
        name = f"{RVN[e]} (corpus {RV2C[e]})" if e in RV2C else f"{RVN[e]} (proposed addition)"
        incs = "—" if inc is None else (f"{inc} / {v} ({pc(inc, v)}%)" if v >= SMALL else f"{inc} / {v}")
        L.append(f"| {p} | {name} | {v} | {incs} | {'—' if ex is None else ex} | {', '.join(f'{k} {n}' for k, n in mc(diff, 2)) or '—'} |")
    ne = [r for _, r, gl in GOLD[p] if gl == []]; coded = sum(bool(llm(r)) for r in ne)
    L.append(f"| {p} | *No entry fits* | {len(ne)} | — ({coded} of {len(ne)} carry a corpus code) | — | {', '.join(f'{k} {n}' for k, n in mc(collections.Counter(NAME[x] for r in ne for x in set(llm(r))), 2)) or '—'} |")

# ---------------------------------------------------------------- the no-entry paragraph and Table 5.5
def tier_of(i): return (PRE.get(J[i]["snapshot_id"]) or {}).get("triage_tier")
pool = {p: [i for i, s in S.items() if s["population"] == p and i in J and tier_of(i)] for p in POPS}
TIERS = (("agree", "three models agree"), ("split", "two agree"), ("disagree", "disagree"))
dis = {p: [x for x in GOLD[p] if tier_of(x[0]) == "disagree"] for p in POPS}
n_wi, g_cand = len(GW), sum(bool(gl) and not any(e in RV2C for e in gl) for _, _, gl in GW)
none_dis = sum(gl == [] for _, _, gl in dis["WITH-AI"]); none_other = [sum(gl == [] for i, _, gl in GW if tier_of(i) == t) / max(1, sum(tier_of(i) == t for i, _, _ in GW)) for t, _ in TIERS[:2]]
taken_other = [sum(tier_of(i) == t for i, _, _ in GW) / max(1, sum(tier_of(i) == t for i in pool["WITH-AI"])) for t, _ in TIERS[:2]]
taken_on = [sum(tier_of(i) == t for i, _, _ in GOLD["ON-AI"]) / max(1, sum(tier_of(i) == t for i in pool["ON-AI"])) for t, _ in TIERS[:2]]
dfk = [gl for _, r, gl in GW if r.get("attack_vector") == "deepfake"]; dfo = collections.Counter(outcome(gl) for gl in dfk)
L += ["", f"**Why the person filed {pc(w_none, n_wi, 0)}% of hand-labelled WITH-AI records under no entry.** The person who hand-labelled filed {w_none} of the "
      f"{n_wi} hand-labelled WITH-AI records ({pc(w_none, n_wi)}%) under none of the rubric's {len(ENTRIES)} entries; {g_cand} more fit only a proposed addition, so "
      f"{w_none + g_cand} ({pc(w_none + g_cand, n_wi)}%) have no Top 10 entry. Design: the hand-labelled set took every record on which the three LLM "
      f"pre-labellers disagreed ({len(dis['WITH-AI'])} of {n_wi} WITH-AI rows, {len(dis['ON-AI'])} of {len(GOLD['ON-AI'])} ON-AI) and "
      f"{100*min(taken_other):.0f}–{100*max(taken_other):.0f}% of the other WITH-AI rows ({100*min(taken_on):.0f}–{100*max(taken_on):.0f}% of the other ON-AI rows); "
      f"{none_dis} of the {w_none} no-entry rows are such rows (no-entry share "
      f"{pc(none_dis, len(dis['WITH-AI']))}% there, {100*min(none_other):.1f}–{100*max(none_other):.1f}% elsewhere). Substance: every rubric entry requires an "
      f"LLM mechanism, and deepfake fraud or abuse imagery from image and voice generators has none, so the person split {len(dfk)} deepfake records three ways: "
      f"{dfo['no entry']} no entry, {dfo['Misinformation']} Misinformation, {dfo['Weaponized LLM Abuse']} Weaponized LLM Abuse. The share describes this sample, not WITH-AI."]

notes_wi = collections.Counter(rv["gold"][J[i]["snapshot_id"]]["notes"] for i, _, gl in GW if gl == []); top_note, top_note_n = mc(notes_wi, 1)[0]
rub = lambda f, phrase: phrase if phrase in (CYCLE / "taxonomy" / f).read_text() else "(phrase not found in the rubric file)"
cve_df = [i for i, r, gl in GW if r.get("attack_vector") == "deepfake" and source_class(r) == "cve/ghsa"]
ncl = {p: sum(i in J for i, s in S.items() if s["population"] == p) for p in POPS}
L += ["", f"**Table 5.5. Why the person could file {pc(w_none, n_wi, 0)}% of hand-labelled WITH-AI records (and {pc(none_on, len(GOLD['ON-AI']), 0)}% of ON-AI) under no entry** (n = {len(GOLD['ON-AI'])} ON-AI and {n_wi} WITH-AI hand-labelled records)", "",
      f"Hand-labelled records by the tier the three LLM pre-labellers put them in (block A), by the corpus attack vector (block B)"
      + (" and by step 4's attacker-objective rule (block C; rule output, not coded)" if METH else "") + ", with the person's outcome; the person's own notes are "
      f"boilerplate ('{top_note}' on {top_note_n} of {w_none} WITH-AI no-entry rows), so the reason is read from the rubric text (Misinformation requires LLM output "
      f"'{rub('LLM09_Misinformation.md', 'trusted and acted upon')}'; Weaponized LLM Abuse requires '{rub('weaponized-llm-abuse.md', 'cyberattacks against third-party targets')}'). "
      f"Deepfake records do not uniformly fit no entry, and the {len(cve_df)} CVE/GHSA deepfake row{'s' if len(cve_df) != 1 else ''} ({', '.join(cve_df) or '—'}) "
      f"{'are' if len(cve_df) != 1 else 'is a'} corpus 'deepfake' mislabel{'s' if len(cve_df) != 1 else ''}.", "",
      f"*A. By pre-label tier.* The pool is the population's records that carry a rank-validation classifier label and a three-LLM pre-label ({len(pool['ON-AI']):,} of the {ncl['ON-AI']:,} ON-AI records with a classifier label, {len(pool['WITH-AI']):,} of {ncl['WITH-AI']:,} WITH-AI).", "",
      "| population | tier | records in pool | hand-labelled n (% of pool) | no entry fits n (% of hand-labelled) | Misinformation | Weaponized LLM Abuse | other entry |", "|---|---|---|---|---|---|---|---|"]
for p in POPS:
    for t, tn in TIERS:
        pool_t = [i for i in pool[p] if tier_of(i) == t]; G = [x for x in GOLD[p] if tier_of(x[0]) == t]
        L.append(f"| {p} | {tn} | {len(pool_t):,} | {npc(len(G), len(pool_t))} | {outcome_cells(G)} |")
    G = [x for x in GOLD[p] if not tier_of(x[0])]
    if G: L.append(f"| {p} | no pre-label | — | {len(G)} | {outcome_cells(G)} |")
L += ["", "*B. By corpus attack vector* (the six most frequent among hand-labelled records, rest pooled).", "",
      "| population | attack vector | hand-labelled | no entry fits n (%) | Misinformation | Weaponized LLM Abuse | other entry |", "|---|---|---|---|---|---|---|"]
for p in POPS:
    vec = collections.Counter(r.get("attack_vector") or "other" for _, r, _ in GOLD[p]); top = [v for v, _ in mc(vec, 6)]
    for v in top: L.append(f"| {p} | {v} | {vec[v]} | {outcome_cells([x for x in GOLD[p] if (x[1].get('attack_vector') or 'other') == v])} |")
    rest = [x for x in GOLD[p] if (x[1].get("attack_vector") or "other") not in top]
    if rest: L.append(f"| {p} | *{len(vec) - len(top)} more value{'s' if len(vec) - len(top) != 1 else ''} (pooled)* | {len(rest)} | {outcome_cells(rest)} |")
ai_on = [x for x in GOLD["ON-AI"] if x[1].get("attack_vector") == "adversarial-input" and x[2] == []]
ai_note = mc(collections.Counter(rv["gold"][J[i]["snapshot_id"]]["notes"] for i, _, _ in ai_on))
if ai_on: L += ["", f"The {len(ai_on)} ON-AI adversarial-input rows with no entry are {', '.join(i for i, _, _ in ai_on)}; the person's notes on them are "
                + "; ".join(f"'{k}' ({v})" for k, v in ai_note) + "."]
if METH:
    L += ["", "*C. WITH-AI by step 4's attacker-objective rule* (rule output, not coded; `out/methodology.json`).", "",
          "| objective (rule) | hand-labelled | no entry fits n (%) | Misinformation | Weaponized LLM Abuse | other entry |", "|---|---|---|---|---|---|"]
    obj = collections.Counter(METH[i]["objective"] for i, _, _ in GW if i in METH)
    for o, v in mc(obj): L.append(f"| {o} | {v} | {outcome_cells([x for x in GW if x[0] in METH and METH[x[0]]['objective'] == o])} |")

# ---------------------------------------------------------------- the lookup: Table 5.6
ON = P["ON-AI"]; n_on = len(ON); on_ch = chan(ON); M = A["mitigations"]
CNT = {p: collections.Counter(t for r in P[p] for t in sound(r)) for p in POPS}
L += ["", "## Which ATLAS mitigations do the corpus's ON-AI categories map to, and which labelled techniques have none?"]
TECHS = sorted({t for ts in XW.values() for t in ts}, key=lambda t: (-sum(t in techs(r) for r in ON), t))
n_links = sum(len(v) for v in XW.values()); n_nomit = sum(1 for c in XW for t in XW[c] if not mits(t))
L += ["", f"**Table 5.6. The corpus's one-technique-per-category lookup: {len(XW)} codes collapse onto {len(TECHS)} techniques, and {n_nomit} of {n_links} links land on a technique with no ATLAS mitigation**", "",
      f"One row per ATLAS technique the corpus's build script derives from OWASP LLM and OWASP Agentic (ASI) codes, with the codes that map to it, the number of "
      f"ATLAS mitigations for it, the ON-AI records carrying it and the share of those labels the lookup reproduces from the record's own codes (an upper bound on "
      f"lookup-derived labels). The lookup is read from the build script at the pinned tag, never run.", "",
      "| ATLAS technique | OWASP codes that map to it | ATLAS mitigations (n) | ON-AI records carrying it n (%) | ON-AI labels the lookup reproduces (%) |", "|---|---|---|---|---|"]
for t in TECHS:
    h = [r for r in ON if t in techs(r)]
    L.append(f"| {label(t)} | {'; '.join(code(c) + (' [1]' if c in SUSPECT else '') for c in via(t))} | {len(mits(t))} | {npc(len(h), n_on)} | {pc(sum(t in backfill(r) for r in h), len(h))} |")
rep = lambda rows: (sum(len(set(techs(r)) & backfill(r)) for r in rows), sum(len(set(techs(r))) for r in rows))
exact = lambda rows: (sum(set(techs(r)) == backfill(r) for r in rows if techs(r)), sum(bool(techs(r)) for r in rows))
def trio(f): return " / ".join(f"{pc(*f(rows))}%" for rows in (R, P["ON-AI"], P["WITH-AI"]))
L += ["", f"[1] {SUSPECT['LLM07']}: this study's recorded judgement, not a measurement; the mitigation tables below drop the technique labels this link alone produces.", "",
      "How much of the label layer is derivable (all records / ON-AI / WITH-AI):", "",
      f"- OWASP LLM code assignments equal to the code the build script seeds from the record's `attack_vector`: {trio(seed_share)}.",
      f"- ATLAS technique labels the lookup reproduces from the record's OWASP codes: {trio(rep)}; per channel ON-AI "
      + ", ".join(f"{x} {pc(*rep(on_ch[x]))}%" for x in CHANNELS) + "; WITH-AI " + ", ".join(f"{x} {pc(*rep(chan(P['WITH-AI'])[x]))}%" for x in CHANNELS) + ".",
      f"- Records whose whole ATLAS set equals the lookup output, among records with any technique: {trio(exact)}."]

# ---------------------------------------------------------------- Table 5.7 reach
L += ["", f"**Table 5.7. ATLAS mitigations reach {pc(sum(any(mits(t) for t in sound(r)) for r in ON), n_on, 0)}% of ON-AI records but "
      f"{pc(sum(any(mits(t) for t in sound(r)) for r in P['WITH-AI']), len(P['WITH-AI']), 0)}% of WITH-AI records, because WITH-AI technique labels are Impact labels**", "",
      "The counterpart of Hamer et al.'s framework measures, after dropping the technique labels the unsound link alone produces. *Technique labels* counts every "
      "(record, technique) pair; *mitigations in use* counts an ATLAS mitigation if any record carries a technique it addresses, which is why WITH-AI shows a high "
      "value there beside a low record reach.", "",
      "| measure | " + " | ".join(POPS) + " |", "|---|---|---|"]
def measure(name, f): L.append(f"| {name} | " + " | ".join(f(p) for p in POPS) + " |")
measure("records", lambda p: f"{len(P[p]):,}")
measure("records with at least one technique label", lambda p: npc(sum(bool(sound(r)) for r in P[p]), len(P[p])))
measure("records with at least one technique that has an ATLAS mitigation", lambda p: npc(sum(any(mits(t) for t in sound(r)) for r in P[p]), len(P[p])))
measure("distinct techniques observed", lambda p: f"{len(CNT[p])}")
measure("techniques with an ATLAS mitigation", lambda p: npc(sum(bool(mits(t)) for t in CNT[p]), len(CNT[p])))
measure("technique labels with an ATLAS mitigation", lambda p: npc(sum(v for t, v in CNT[p].items() if mits(t)), sum(CNT[p].values())))
measure("technique labels on ATT&CK-adapted techniques (own or parent's ATT&CK reference) with no ATLAS mitigation", lambda p: npc(sum(v for t, v in CNT[p].items() if not mits(t) and attack_ref(t)), sum(CNT[p].values())))
measure("technique labels on Impact-tactic techniques", lambda p: npc(sum(v for t, v in CNT[p].items() if "Impact" in tactics(t)), sum(CNT[p].values())))
measure("mitigations in use (ATLAS mitigations addressing at least one observed technique)", lambda p: npc(sum(any(m in mits(t) for t in CNT[p]) for m in M), len(M)))

# ---------------------------------------------------------------- Table 5.8 mitigations grouped by technique set
hit = {m: frozenset(t for t in CNT["ON-AI"] if m in mits(t)) for m in M}
groups = collections.defaultdict(list)
for m in M:
    if hit[m]: groups[hit[m]].append(m)
cov = {hs: [r for r in ON if sound(r) & hs] for hs in groups}
ranked = sorted(groups, key=lambda hs: (-len(cov[hs]), -len(hs), sorted(groups[hs])))
def reached(hs): return [NAME[c] for c in sorted(XW, key=lambda c: (c[:3] != "LLM", c)) if c not in SUSPECT and any(t in hs for t in XW[c])]
L += ["", f"**Table 5.8. ON-AI: {' / '.join(M[m]['name'] for m in groups[ranked[0]])} addresses {pc(len(cov[ranked[0]]), n_on, 0)}% of records; mitigations grouped where they address the same techniques, per channel** "
      f"({sum(len(v) for v in groups.values())} of {len(M)} ATLAS mitigations address at least one ON-AI record; {len(ranked)} rows)", "",
      "A mitigation *addresses* a record if the record carries a technique ATLAS links it to (its `mitigates` relationship, to the technique or its parent); "
      "this is neither efficacy nor adoption. Mitigations that address an identical set of observed techniques share a row; *OWASP categories reached* names "
      "the entries whose lookup technique the row addresses, and a dash means the row is reached only through techniques the corpus assigned directly. *ATLAS category* "
      "and *lifecycle phases* are ATLAS's own tags for the kind of control (Policy, Technical - AI, Technical - Cyber) and the stages of the model lifecycle it belongs to.", "",
      "| mitigation(s) | ATLAS category | lifecycle phases | % of cve/ghsa | % of harm-db | % of research/other | all ON-AI records n (%) | techniques addressed (n) | OWASP categories reached |",
      "|---|---|---|---|---|---|---|---|---|"]
for hs in ranked:
    ms = sorted(groups[hs]); ids = set(id(r) for r in cov[hs])
    L.append(f"| {'; '.join(m + ' ' + M[m]['name'] for m in ms)} | {', '.join(uniq(c for m in ms for c in M[m]['categories']))} | "
             f"{', '.join(uniq(l for m in ms for l in M[m]['lifecycle']))} | " + " | ".join(pc(sum(id(r) in ids for r in on_ch[x]), len(on_ch[x])) for x in CHANNELS)
             + f" | {npc(len(cov[hs]), n_on)} | {len(hs)} | {', '.join(reached(hs)) or '—'} |")
g0 = ranked[0]; sc_t = set(XW["LLM04"]) | set(XW["ASI04"])
only_sc = sum((sound(r) & g0) <= sc_t for r in cov[g0])
second = {x: sorted(ranked[1:], key=lambda hs: (-sum(source_class(r) == x for r in cov[hs]), sorted(groups[hs])))[0] for x in CHANNELS}
L += ["", f"{'; '.join(M[m]['name'] for m in sorted(groups[g0]))} reaches " + ", ".join(f"{pc(sum(source_class(r) == x for r in cov[g0]), len(on_ch[x]))}% of {x}" for x in CHANNELS)
      + f" ON-AI records, {only_sc} of its {len(cov[g0]):,} records only through the {NAME['LLM04']} / {NAME['ASI04']} label. The second row per channel is "
      + "; ".join(f"{x}: {' / '.join(M[m]['name'] for m in sorted(groups[second[x]]))} ({pc(sum(source_class(r) == x for r in cov[second[x]]), len(on_ch[x]))}%)" for x in CHANNELS) + "."]

# ---------------------------------------------------------------- Table 5.9 gaps
gaps = sorted((t for t in CNT["ON-AI"] if not mits(t)), key=lambda t: (-CNT["ON-AI"][t], t)); top_g, rest_g = gaps[:10], gaps[10:]
only_un = [r for r in ON if sound(r) and not any(mits(t) for t in sound(r))]
L += ["", f"**Table 5.9. ON-AI: the two most frequent technique labels ({tname(gaps[0]).lower()} {pc(CNT['ON-AI'][gaps[0]], n_on, 0)}%, "
      f"{tname(gaps[1]).lower()} {pc(CNT['ON-AI'][gaps[1]], n_on, 0)}%) have no ATLAS mitigation, though ATT&CK mitigates both** (top {len(top_g)} of {len(gaps)})", "",
      "Techniques labelled on ON-AI records for which ATLAS lists no mitigation, most frequent first, with the share of each channel's ON-AI records carrying "
      "them. *ATT&CK technique* is the Enterprise ATT&CK technique ATLAS adapted the entry from: where one is given, ATT&CK publishes mitigations that ATLAS has "
      "not imported, so the gap is in the framework's coverage; a dash in the OWASP column means the corpus assigned the technique directly, not through the lookup. "
      "*Tactic* is the ATLAS tactic the technique is filed under: the adversary's goal at that step (Initial Access, Execution, Impact and so on).", "",
      "| technique | tactic | ON-AI records n (%) | % of cve/ghsa | % of harm-db | % of research/other | OWASP categories that lead to it | ATT&CK technique |", "|---|---|---|---|---|---|---|---|"]
for t in top_g:
    L.append(f"| {label(t)} | {', '.join(tactics(t)) or '—'} | {npc(CNT['ON-AI'][t], n_on)} | " + " | ".join(pc(sum(t in sound(r) for r in on_ch[x]), len(on_ch[x])) for x in CHANNELS)
             + f" | {', '.join(code(c) for c in via(t)) or '—'} | {attack_ref(t) or '—'} |")
if rest_g:
    rr = [r for r in ON if sound(r) & set(rest_g)]
    L.append(f"| *{len(rest_g)} more techniques (pooled)* | — | {npc(len(rr), n_on)} | " + " | ".join(pc(sum(bool(sound(r) & set(rest_g)) for r in on_ch[x]), len(on_ch[x])) for x in CHANNELS) + " | — | — |")
L += ["", f"{len(only_un)} ON-AI records carry only techniques with no ATLAS mitigation; {mc(collections.Counter(source_class(r) for r in only_un), 1)[0][1]} of them are "
      f"{mc(collections.Counter(source_class(r) for r in only_un), 1)[0][0]} records."]

# ---------------------------------------------------------------- Use cases
ioh = "LLM10"; g0_ch = [100 * sum(source_class(r) == x for r in cov[g0]) / len(on_ch[x]) for x in CHANNELS]
fill = {f: sum(bool(r.get(f)) for r in R) for f in ("mitigations", "impact", "discovery_method")}
L += ["", "## Use cases", "", "What the tables support today, each with its caveat.", "",
      f"- *Deployers of AI systems.* Table 5.1 shows, per disclosure channel, which categories the corpus labelling places above the community vote ({NAME[ioh]}: corpus "
      f"{ordn(crank_on[ioh])}, vote {ordn(rv['ranks'][C2RV[ioh]]['vote_rank'])}) and Table 5.4 where a human reader kept or changed the corpus's label. Table 5.8 shows "
      f"{'; '.join(M[m]['name'] for m in sorted(groups[g0]))} reaching {min(g0_ch):.0f}–{max(g0_ch):.0f}% of ON-AI records per channel; Table 5.9 shows that the two "
      f"most frequent technique labels ({tname(gaps[0]).lower()} {pc(CNT['ON-AI'][gaps[0]], n_on, 0)}%, {tname(gaps[1]).lower()} {pc(CNT['ON-AI'][gaps[1]], n_on, 0)}%) "
      f"have no ATLAS mitigation. Caveat: labels are keyword rules, and Supply Chain marks the CVE channel ({pc(sc_cve, len(cve_all), 0)}%).",
      f"- *Researchers.* Table 5.3 shows which categories the index sees realized but rarely demonstrated ({', '.join(f'{NAME[c]} {100*demo_on[c]:.0f}%' for c in lo_d)}) "
      f"and the reverse ({', '.join(f'{NAME[c]} {100*demo_on[c]:.0f}%' for c in hi_d)}); Table 4.6 and the unstated rows of "
      f"Tables 4.1–4.5 size the coding work. Caveat: 'demonstrated' tracks the research channel, {pc(sum(source_class(r) == 'research/other' for r in R), len(R), 0)}% of the corpus.",
      f"- *Framework authors.* Table 5.5: {w_none} of {n_wi} hand-labelled WITH-AI records fit none of {len(ENTRIES)} entries, mostly deepfake fraud and abuse imagery; Table 5.6: one "
      f"lookup link produces every {label(XW['LLM07'][0])} label on ON-AI records; Table 5.2: {RVN[WLA]} absorbs {hum_wi[WLA]} hand labels with no corpus code.",
      f"- *Database maintainers.* Table 4.6: `mitigations` and `impact` are filled on {pc(sum(bool(r.get('mitigations')) for r in ON), n_on)}% of ON-AI and {pc(sum(bool(r.get('mitigations')) for r in P['WITH-AI']), len(P['WITH-AI']))}% of WITH-AI records, "
      f"`discovery_method` on {fill['discovery_method']} of {len(R):,} records; Table 1.10: OWASP codes mark channels.", "",
      "**Not supported:** prevalence in the world; a corrected or human-ranked Top 10; attack chains or sequences; "
      "mitigation adoption or efficacy; trends over time; attribution or exploitation status; technique-level statements about how attackers operated."]

# ---------------------------------------------------------------- Limitations of the data
frame = {x: collections.Counter(S[i]["population"] for i in S if S[i]["source_class"] == x and S[i]["population"] in ("ON-AI", "WITH-AI", "BOTH")) for x in CHANNELS}
med = lambda rows: median([len(r.get("description") or "") for r in rows])
ADV = re.compile(r"attacker|threat actor|hacker|adversar|campaign|exploited|abused|scam|fraud|extort|stole|breach|malicious|\bAPT\b|state-sponsored|cybercrim|ransomware|phish|impersonat|weaponi[sz]", re.I)
wv = [C[i] for i in S if S[i]["rule"] == "with-vector"]; wv_silent = sum(not ADV.search(text(r)) for r in wv)
gold_ids = set(rv["gold"]); g_unres = len(gold_ids & set(JR["unresolved"])); g_rec = sum(v["gold_labels"] is not None for v in J.values())
g_land = sum(len([i for i in v["snapshot_ids"] if i in gold_ids]) for v in J.values())
blind_eq = blind_agreement(rv)[0]
tier_g = collections.Counter("disagree" if PRE[i]["triage_tier"] == "disagree" else ("oos" if PRE[i]["consensus"] == "out-of-scope" else "entry") for i in gold_ids if i in PRE)
quota = collections.Counter((PRE[i]["consensus"], PRE[i]["agreement"]) for i in gold_ids if i in PRE and PRE[i]["triage_tier"] != "disagree" and PRE[i]["consensus"] != "out-of-scope")
cap = {a: max(v for (c, aa), v in quota.items() if aa == a) for a in ("3-of-3", "2-of-3")}    # the per-entry quota, recovered as the largest cell
multi = [v for v in J.values() if len(v["gold_all"]) > 1]; multi_dis = sum(len({tuple(g) for g in v["gold_all"]}) > 1 for v in multi)
samp = {i for s in json.load(open(CYCLE / "calibration/samples.json"))["samples"] for i in s["incident_ids"]} & gold_ids
none_t = {t: (sum(gl == [] for i, _, gl in GW if tier_of(i) == t), sum(tier_of(i) == t for i, _, _ in GW)) for t, _ in TIERS}
taken_t = {t: (sum(tier_of(i) == t for i, _, _ in GW), sum(tier_of(i) == t for i in pool["WITH-AI"])) for t, _ in TIERS}
cover = {p: (sum(1 for i in S if S[i]["population"] == p and i in J), len(P[p])) for p in POPS}
f26 = [i for i in S if S[i]["population"] in ("ON-AI", "WITH-AI", "BOTH") and C[i]["year"] == 2026]
popJ = collections.Counter(S[i]["population"] for i in J); wide = sum(x["lambda_ci"][1] - x["lambda_ci"][0] >= 10 for x in rv["ranks"].values())
wide_shown = sum(x["lambda_ci"][1] - x["lambda_ci"][0] >= 10 for e, x in rv["ranks"].items() if e not in FRAME_BLIND); n_dates = len({str(r.get("added")) for r in R})
full_q = sum(1 for e in {c for c, _ in quota} if quota[(e, "3-of-3")] + quota[(e, "2-of-3")] == cap["3-of-3"] + cap["2-of-3"])
diff_codes = sum(C2RV[c] != c for c in NM["corpus"])
y19 = [r for r in R if r["year"] >= 2019]; added = collections.Counter(str(r["added"])[:7] for r in R)
hmax = max(str(r["date"]) for r in R if source_class(r) == "harm-db"); cmax = max(str(r["date"]) for r in cve_all)
late = {p: sum(str(r["date"])[:7] > hmax[:7] and source_class(r) == "cve/ghsa" for r in P[p]) for p in POPS}
prec = {p: collections.Counter(len(str(r["date"])) for r in P[p]) for p in POPS}
stub = [r for r in P["WITH-AI"] if r.get("description_provenance") == "original"]
on_cwe = collections.Counter(x for r in ON for x in set(r.get("cwe_ids") or [])); cwe_pi = sum("CWE-1427" in (r.get("cwe_ids") or []) for r in R)
pi_cve = [r for r in ON if r.get("attack_vector") == "prompt-injection" and r.get("cve_ids")]
n_tech = len(A["techniques"]); n_mit_t = sum(bool(mits(t)) for t in A["techniques"]); n_attack_t = sum(bool(attack_ref(t)) for t in A["techniques"])
n_attack_m = sum(bool(mits(t)) for t in A["techniques"] if attack_ref(t))
lab_on, lab_wi = sum(CNT["ON-AI"].values()), sum(CNT["WITH-AI"].values())
un_on = sum(v for t, v in CNT["ON-AI"].items() if not mits(t)); un_att = sum(v for t, v in CNT["ON-AI"].items() if not mits(t) and attack_ref(t))
imp_wi = sum(v for t, v in CNT["WITH-AI"].items() if "Impact" in tactics(t))
unst = ({d: sum(METH[i].get(d) == "unstated" for i in S if i in METH and S[i]["population"] == pp) for pp, dims in (("ON-AI", ("entry_point", "target")), ("WITH-AI", ("ai_role", "objective"))) for d in dims} if METH else None)
retr_on = [i for i, s in S.items() if s["population"] == "ON-AI" and C[i].get("status") == "retracted"]
mit_f = {p: sum(bool(r.get("mitigations")) for r in P[p]) for p in POPS}
L += ["", "## Limitations of the data", "",
      "genai_incidents is an index of other trackers in which every label is the output of a rule, so this study uses it to find and stratify incidents, never "
      "to measure them. The items below are ordered by how much each threatens the study's claims; each carries the number that bounds the damage and the table that reports it.", "",
      f"1. **Channel confounding.** Population tracks disclosure channel (cve/ghsa {frame['cve/ghsa']['ON-AI']:,} of {sum(frame['cve/ghsa'].values()):,} frame records ON-AI; "
      f"harm-db {frame['harm-db']['WITH-AI']:,} of {sum(frame['harm-db'].values()):,} WITH-AI; research/other {frame['research/other']['ON-AI']:,} of {sum(frame['research/other'].values()):,} ON-AI), "
      f"as do description length (median {med(cve_all)} / {med([r for r in R if source_class(r) == 'harm-db'])} / {med([r for r in R if source_class(r) == 'research/other'])} characters), "
      f"date precision, demonstrated share and the end of the record series (harm-db stops {hmax[:7]}, cve/ghsa runs to {cmax[:7]}). Any pooled ON/WITH ratio or "
      f"cross-population comparison on description-derived fields compares channels (Tables 2.2, 1.6, 1.7, 2.10).",
      f"2. **Labels are rule outputs.** {pc(*seed_share(R))}% of OWASP LLM code assignments equal the code seeded from `attack_vector` (WITH-AI {pc(*seed_share(P['WITH-AI']))}%), and "
      f"{pc(*rep(R))}% of ATLAS technique labels (ON-AI {pc(*rep(ON))}%, WITH-AI {pc(*rep(P['WITH-AI']))}%; ON-AI research/other {pc(*rep(on_ch['research/other']), 0)}%) are reproducible from the "
      f"build script's OWASP→ATLAS lookup, an upper bound on lookup-derived labels. The corpus ranks in Tables 5.1–5.2 and the mitigation ranking in Table 5.8 rank keyword rules, not observed techniques (Table 5.6).",
      f"3. **Supply Chain is a channel marker.** {sc_cve:,} of {len(cve_all):,} CVE/GHSA records ({pc(sc_cve, len(cve_all))}%) carry corpus LLM04 regardless of attack vector "
      f"({', '.join(f'{v} {n:,}' for v, n in mc(collections.Counter(r.get('attack_vector') or 'other' for r in cve_all if 'LLM04' in llm(r)), 3))}), arriving with the upstream feed; "
      f"within ON-AI it sits on {pc(sum('LLM04' in llm(r) for r in on_ch['cve/ghsa']), len(on_ch['cve/ghsa']))}% of cve/ghsa and {pc(sum('LLM04' in llm(r) for r in on_ch['harm-db']), len(on_ch['harm-db']))}% of harm-db records. "
      f"Its corpus rank {crank_on['LLM04']} in ON-AI is a channel artefact (Tables 1.10, 5.1).",
      f"4. **The split is rule-based.** {wv_silent:,} of {len(wv):,} WITH-AI rows assigned by the corpus vector alone ({pc(wv_silent, len(P['WITH-AI']))}% of WITH-AI) contain no adversary word in the searched text; "
      f"{sum(source_class(r) == 'cve/ghsa' for r in P['WITH-AI'])} WITH-AI rows are CVE/GHSA records; {sum(S[i]['rule'] == 'conventional-exploit-of-ai-tooling' for i in S)} conventional-exploit rows enter ON-AI on security-register words; "
      f"{sum(S[i]['population'] == 'NONE' and C[i]['category'] == 'vulnerability-disclosure' for i in S):,} vulnerability disclosures are gated to NONE. Population sizes carry an unmeasured false-positive and false-negative rate (Table 2.5).",
      f"5. **The hand-labelled set is a quota sample from LLM pre-labels, by one coder.** {len(gold_ids):,} rows: up to {cap['3-of-3']} unanimous and {cap['2-of-3']} majority rows per LLM-consensus entry "
      f"({tier_g['entry']} rows; {full_q} entries reach the cap of {cap['3-of-3'] + cap['2-of-3']}), all {tier_g['disagree']} rows with no majority, and {tier_g['oos']} rows whose pre-label majority was 'no entry'; one person who saw the three LLM votes after a blind read "
      f"(blind label = final label on {pc(blind_eq, len(gold_ids))}%); only {len(samp)} of the {len(gold_ids):,} are in rank-validation's `samples.json`, and the cycle marks itself NON-PUBLISHABLE. "
      f"Hand-labelled counts support 'where labellings disagree' and the existence of no-entry rows, never a ranking or prevalence (Tables 1.14, 5.1–5.2).",
      f"6. **No-entry shares describe the sample.** {none_t['disagree'][0]} of the {w_none} WITH-AI no-entry rows are disagree-tier rows, a tier taken in full ({taken_t['disagree'][0]} of {taken_t['disagree'][1]}) "
      f"while {100*min(taken_other):.0f}–{100*max(taken_other):.0f}% of other rows were taken; no-entry runs {' / '.join(pc(*none_t[t]) + '%' for t in ('disagree', 'split', 'agree'))} across the disagree / split / agree tiers. "
      f"The {pc(w_none, n_wi)}% is not the share of WITH-AI records that fit no entry, and no CI is attached (Table 5.5).",
      f"7. **Join losses and merged duplicates.** Of {len(gold_ids):,} hand-labelled rows {g_unres} no longer resolve to a current id and {g_land:,} land on {g_rec:,} records ({g_land - g_rec} collapse onto records already counted; "
      f"{len(multi)} records received two or more hand labels and {multi_dis} of them disagreeing ones, of which the record's own label, else the first in rank-validation's file order, is kept; Tables 5.1–5.2 name those in each population); "
      f"of {sum(len(v) for v in rv['labels'].values()):,} classifier rows {len(JR['unresolved'])} do not resolve and {JR['collapsed']} collapse. Rank-validation covers "
      f"{pc(*cover['ON-AI'])}% of ON-AI and {pc(*cover['WITH-AI'])}% of WITH-AI ({pc(sum(i in J for i in f26), len(f26))}% of frame records dated 2026), so its columns describe the pre-May-2026 part of each population (Table 1.13).",
      f"8. **The data rank is a whole-snapshot statistic with weak concordance.** Of the {len(J):,} joined records {pc(popJ['NONE'], len(J))}% are NONE and {pc(popJ['ON-AI'] + popJ['WITH-AI'], len(J))}% ON-AI or WITH-AI ({pc(popJ['ON-AI'] + popJ['WITH-AI'] + popJ['BOTH'], len(J))}% with BOTH, Table 1.13); "
      f"weighted κ = {KAPPA:.2f} ({sg(KCI[0])}, {sg(KCI[1])}) over {rv['concordance']['measurable_count']} of {rv['concordance']['total_count']} entries; {len(FRAME_BLIND)} entries are frame-blind; "
      f"{wide} of {len(rv['ranks'])} data-rank intervals ({wide_shown} of the {len(rv['ranks']) - len(FRAME_BLIND)} with a data rank) span 10 or more places, and the ai-harm records have no precision measurement. Vote-vs-data is the other project's finding, used for expectation-setting only (Table 1.15).",
      f"9. **OWASP numbering mismatch.** {diff_codes} of the ten entries carry different codes in the corpus and in rank-validation "
      f"({'; '.join(f'corpus {c} {NAME[c]} = rv {C2RV[c]}' for c in ('LLM04', 'LLM07', 'LLM10'))}), and rank-validation's quick-reference names for the proposed entries are stale. Every join is by name and every table prints names (Table 1.0).",
      f"10. **Record year is ingestion.** {sum(r['year'] == 2026 for r in y19):,} of {len(y19):,} records dated 2019 or later ({pc(sum(r['year'] == 2026 for r in y19), len(y19))}%) carry 2026; all records were added in "
      f"{len(added)} added-months of 2026, {n_dates} distinct `added` dates ({', '.join(f'{k} {v:,}' for k, v in sorted(added.items()))}; `first_seen` equals `added` by construction); harm-database records end {hmax} while CVE/GHSA records run to {cmax} "
      f"(ON-AI has {late['ON-AI']} CVE/GHSA rows after the last harm-db month, WITH-AI {late['WITH-AI']}). No table is a trend (Tables 1.5, 1.6, 2.11).",
      f"11. **Date precision.** ON-AI dates are {pc(prec['ON-AI'][7], n_on)}% month-only (CVE rows), WITH-AI {pc(prec['WITH-AI'][10], len(P['WITH-AI']))}% day-level and {pc(prec['WITH-AI'][4], len(P['WITH-AI']))}% year-only, "
      f"so the populations cannot be placed on a common axis finer than a year (Tables 1.7, 2.10).",
      f"12. **Descriptions are short and partly stubs.** Median {med(R)} characters (ON-AI {med(ON)}, WITH-AI {med(P['WITH-AI'])}); {len(stub)} WITH-AI records ({pc(len(stub), len(P['WITH-AI']))}%) are AIAAIC facts-only stubs "
      f"(`description_provenance == 'original'`, median {med(stub)} characters) that defeat every keyword rule; {sum(r['title'].rstrip().endswith(('…', '...')) for r in R)} titles end in an ellipsis. "
      f"The corpus is a frame; coding is from primary references (Tables 4.4b, 4.6).",
      f"13. **CVE records are coded as conventional weaknesses.** {pc(sum(bool(r.get('cve_ids') or r.get('cwe_ids')) for r in ON), n_on)}% of ON-AI carries a CVE or CWE; the top ON-AI CWEs are "
      f"{', '.join(k for k, _ in mc(on_cwe, 5))}; CWE-1427 (prompt injection) appears on {cwe_pi} corpus records while {len(pi_cve)} ON-AI prompt-injection CVEs carry "
      f"{', '.join(k for k, _ in mc(collections.Counter(x for r in pi_cve for x in set(r.get('cwe_ids') or [])), 4))}. Step 4's 'CVE/CWE present' is an upper bound on 'needed a software bug' (Table 4.3).",
      f"14. **ATLAS gaps are partly framework artefacts.** ATLAS {PINS['atlas_release']} mitigates {n_mit_t} of {n_tech} techniques and {n_attack_m} of {n_attack_t} ATT&CK-adapted techniques in ATLAS; "
      f"{pc(un_on, lab_on)}% of ON-AI technique labels sit on unmitigated techniques ({un_att:,} on ATT&CK-adapted ones, counting a sub-technique's parent reference) and {pc(imp_wi, lab_wi)}% of WITH-AI labels are Impact outcomes. "
      f"Table 5.9 mixes 'ATLAS has not imported ATT&CK mitigations' with 'no known mitigation', and nothing records whether a victim had any control.",
      (f"15. **Rule-based dimensions have large 'unstated' shares and known defects.** Entry point unstated {pc(unst['entry_point'], n_on)}% of ON-AI, target {pc(unst['target'], n_on)}%, "
       f"AI medium {pc(unst['ai_role'], len(P['WITH-AI']))}% of WITH-AI, objective {pc(unst['objective'], len(P['WITH-AI']))}%; substring defects are listed in Table 4.7 with before/after counts. "
       f"Every step 4 share is a lower bound and the complement is the hand-coding workload (Tables 4.1b, 4.4b, 4.7)." if METH else
       "15. **Rule-based dimensions have large 'unstated' shares and known defects.** The unstated shares of entry point, target, AI medium and objective are in step 4 "
       "(`out/methodology.json` was not present when this file was generated; see step 4). Every step 4 share is a lower bound and the complement is the hand-coding workload (Tables 4.1b, 4.4b, 4.7)."),
      f"16. **Exploitation, attribution and housekeeping fields are nearly empty.** `exploited_in_wild` is true on {sum(r.get('exploited_in_wild') is True for r in R)} records "
      f"({sum(r.get('exploited_in_wild') is True for r in ON)} ON-AI), `discovery_method` on {fill['discovery_method']}, `mitigations` on {mit_f['ON-AI']} ON-AI and {mit_f['WITH-AI']} WITH-AI records (as recommendations, not controls the victim had); "
      f"{sum(r.get('status') == 'retracted' for r in R)} retracted records remain ({len(retr_on)} in ON-AI); {sum((r.get('source_count') or 1) > 1 for r in R):,} multi-source records are counted under their first-match channel. "
      f"Realized vs demonstrated rests on the record-type field alone (Table 4.6)."]
write("s05_techniques.md", L)
