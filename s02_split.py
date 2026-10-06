#!/usr/bin/env python3
"""s02_split.py — Step 2. Whose AI is it? Split the corpus into attacks ON AI and attacks WITH AI.

Deciding question: whose asset is the AI system?
  ON-AI   — the AI system belongs to the victim and the adversary subverts it (it is the target or vector).
  WITH-AI — the AI is the adversary's instrument against a conventional target.
  BOTH    — both signals present (most are threat reports on criminal LLM services or influence operations).
  UNRESOLVED — adversary vocabulary present, no population signal; hand review.
  NONE    — no adversary (disclosure without exploitation, operator harm, model failure).
Rules are deterministic over attack_vector, the record type (category) and the title + description + affected text;
they do not read CVE/CWE presence. Output: out/split.json (id -> population, rule, ...) and out/s02_split.md.
"""
import collections, json, re
from common import load_full, load_rv, join_rv, owasp_names, source_class, text, table, write, READ, CHANNELS

ON_VEC = {"prompt-injection", "indirect-prompt-injection", "jailbreak", "tool-abuse", "agent-hijack", "memory-poisoning",
          "model-poisoning", "backdoor", "adversarial-input", "evasion", "model-extraction", "model-inversion", "membership-inference", "sandbox-escape"}
WITH_VEC = {"deepfake", "phishing", "csam-generation"}
CODE_VEC = {"rce", "ssrf", "sql-injection", "command-injection", "path-traversal", "deserialization", "xss", "auth-bypass",
            "info-disclosure", "dos", "csrf", "data-exfiltration", "supply-chain", "malware"}
ADV = re.compile(r"attacker|threat actor|hacker|adversar|campaign|exploited|abused|scam|fraud|extort|stole|breach|malicious|\bAPT\b|state-sponsored|cybercrim|ransomware|phish|impersonat|weaponi[sz]", re.I)
WITH_KW = re.compile(r"deepfake|voice ?clon|synthetic (media|audio|video|image)|ai-generated (image|video|audio|voice|content|phish|malware)|used (chatgpt|claude|gemini|an? (llm|ai|chatbot|model)) to|ai-(assisted|enabled|powered|driven) (attack|phish|scam|fraud|malware|hack|cyber)|influence operation|disinformation campaign|llm-(assisted|generated|written) malware|wormgpt|fraudgpt", re.I)
ON_KW = re.compile(r"prompt injection|jailbr|system prompt|guardrail|exfiltrat\w+ (via|through) (the )?(model|agent|copilot|assistant|chatbot)|tool (call|invocation)|mcp server|agent (hijack|abuse)|model (theft|extraction|poison)|training data poison|rag poison|memory poison", re.I)
# Diagnostic patterns for Table 2.5 and 2.12 only; they assign nothing.
AI_INSTR = re.compile(r"ai[- ](generated|cloned|manipulated|powered|driven|enabled|assisted)|generated (by|with|using) (ai|chatgpt|generative)|us(ed|ing) (chatgpt|generative ai|ai (to|for|songs|images|voice))|voice (clon|scam|mimic)|chatbots?\b|deepfake|synthetic", re.I)
FRAUD_DET = re.compile(r"fraud[- ](detect|predict|scor|risk|algorithm|review|investigation|model|system)|detect\w* (\w+ )?(fraud|scam)|flag\w* .{0,40}(fraud|scam)|(prevent|block)\w* .{0,30}(fraud|scam)|anti-fraud|welfare|benefit", re.I)
AD_CAMP = re.compile(r"(\bad|ads|advertising|marketing|promotional|tourism|merchandise) campaign|campaign ad\b|#\w+ campaign", re.I)
FAIR = re.compile(r"\bbias|discriminat|fairness|disparit|racial|gender", re.I)
STUB = re.compile(r"Tracked by the OECD|AI Incident Database \(AIID\) entry|AIAAIC-tracked incident")
ATTACKER_ENTRIES = ("LLM01", "NEW-WLA", "NEW-MTIE")  # rank-validation ids: Prompt Injection, Weaponized LLM Abuse, MCP Tool Interface Exploitation

def classify(r):
    av = r.get("attack_vector") or "other"; t = text(r)
    adversary = av in ON_VEC or av in WITH_VEC or bool(ADV.search(t))
    on, with_ = av in ON_VEC or bool(ON_KW.search(t)), av in WITH_VEC or bool(WITH_KW.search(t))
    if r.get("category") == "vulnerability-disclosure" and not (on or with_): return "NONE", "disclosure-without-exploitation"
    if on and with_: return "BOTH", "on+with signals"
    if on: return "ON-AI", "on-vector" if av in ON_VEC else "on-vocabulary"
    if with_: return "WITH-AI", "with-vector" if av in WITH_VEC else "with-vocabulary"
    if adversary and av in CODE_VEC: return "ON-AI", "conventional-exploit-of-ai-tooling"
    if adversary: return "UNRESOLVED", "adversary-vocabulary-no-population-signal"
    return "NONE", "no-adversary"

C = load_full(); S = {}
for i, r in C.items():
    pop, rule = classify(r)
    S[i] = {"population": pop, "rule": rule, "year": r["year"], "tier": r["tier"], "category": r["category"],
            "attack_vector": r.get("attack_vector"), "source_class": source_class(r), "primary_reference": (r.get("references") or [{}])[0].get("url")}
json.dump(S, open("out/split.json", "w"), indent=0)

# ---- helpers (local; candidates for common.py)
P = lambda p: [C[i] for i, s in S.items() if s["population"] == p]
ON, WI, BO, UN, NO = (P(p) for p in ("ON-AI", "WITH-AI", "BOTH", "UNRESOLVED", "NONE"))
F = [C[i] for i, s in S.items() if s["population"] in ("ON-AI", "WITH-AI", "BOTH")]  # corpus order, so the seeded bootstrap is reproducible
pct = lambda a, b: f"{100*a/b:.1f}" if b else "—"
def share_word(a, b):
    """Coded wording for a share: 'half' only for 45–55%, otherwise '<k> in five'."""
    p = 100 * a / b
    return "half" if 45 <= p <= 55 else ["none", "one", "two", "three", "four", "five"][round(p / 20)] + " in five"
vec = lambda r: r.get("attack_vector") or "other"
is_avid = lambda r: any(s.startswith("AVID") for s in r["source_ids"])
has_cve = lambda r: bool(r.get("cve_ids") or r.get("cwe_ids"))
members = lambda c: ", ".join(f"{k} {v}" for k, v in c)
rv = load_rv(); J = join_rv(C, rv)["rows"]; NM = owasp_names(rv)["rv"]
name = lambda e: NM.get(e, e)
def hand(rs, top=3):
    """'k hand-labelled: no entry fits a; Name n, Name n' for the hand-labelled rows among records rs (names, never numbers)."""
    g = [J[r["id"]]["gold_labels"] for r in rs if r["id"] in J and J[r["id"]]["gold_labels"] is not None]
    if not g: return "none"
    oos = sum(x == [] for x in g); c = collections.Counter(name(e) for x in g for e in x)
    return f"{len(g)}: " + "; ".join(([f"no entry fits {oos}"] if oos else []) + [f"{k} {v}" for k, v in c.most_common(top)])
def by_channel(rs, pred):
    """n per channel among rs satisfying pred, as 'cve/ghsa a, harm-db b, research/other c' (zeros dropped)."""
    c = collections.Counter(source_class(r) for r in rs if pred(r)); return ", ".join(f"{ch} {c[ch]:,}" for ch in CHANNELS if c[ch])

# ---- header
ta = [r for r in BO if vec(r) == "tool-abuse"]
ch_frame = {ch: collections.Counter(S[r["id"]]["population"] for r in F if source_class(r) == ch) for ch in CHANNELS}
ch_share = lambda ch, p: 100 * ch_frame[ch][p] / sum(ch_frame[ch].values())
L = [f"# Step 2 — Whose AI is it? Splitting {len(C):,} records into attacks ON AI and attacks WITH AI", "",
     "Generated by `s02_split.py` (`make s02`); do not edit by hand. Fixed rules over the corpus `attack_vector`, the record type (`category`) "
     "and the title + description + affected text assign each record one population; CVE/CWE presence is not read. The deciding question is "
     "whose asset the AI system is:", "",
     "- **ON-AI**: the AI system belongs to the victim and the adversary subverts it (it is the target or the vector).",
     "- **WITH-AI**: the AI is the adversary's instrument against a conventional target.",
     f"- **BOTH**: both signals are present. {len(ta)} of the {len(BO)} BOTH records carry the vector `tool-abuse`: "
     f"{sum(r['category'] == 'threat-report' for r in ta)} threat reports and {sum(r['category'] == 'real-world' for r in ta)} incidents on criminal LLM "
     "services (WormGPT, FraudGPT) and state-linked influence operations that used ChatGPT, where the model is misused and the output is aimed at a third party.",
     "- **UNRESOLVED**: an attacker word is present but nothing says which population; Table 2.12 sizes the hand review.",
     "- **NONE**: no adversary (a disclosure without exploitation, operator harm, or a model failure).", "",
     f"The *adversary frame* is ON-AI + WITH-AI + BOTH ({len(F):,} records). The central finding is Table 2.2: the population tracks the disclosure channel "
     f"(CVE/GHSA {ch_share('cve/ghsa', 'ON-AI'):.0f}% ON-AI, harm databases {ch_share('harm-db', 'WITH-AI'):.0f}% WITH-AI), so every later "
     "per-population share is also reported within channel; Table 2.5 lists where the rules are known to be weak and Table 2.13 checks the split against an "
     "independent person's labels. " + READ]

# ---- 2.1 all records
nn = collections.Counter(S[r["id"]]["rule"] for r in NO)
L += ["", "## How many records involve an adversary?"]
L += table(f"How many records involve an adversary? {share_word(len(NO), len(C)).capitalize()} do not", list(S.values()), lambda s: s["population"], num="2.1",
           desc=f"One population per record. NONE is two rules: {nn['disclosure-without-exploitation']:,} vulnerability disclosures with no ON or WITH signal "
                f"and {nn['no-adversary']:,} records with no attacker word.")

# ---- 2.2 channel (central finding)
L += ["", "## Which channel sees which attacks?", "",
      f"**Table 2.2. Which channel sees which attacks? CVE/GHSA {ch_share('cve/ghsa', 'ON-AI'):.0f}% ON-AI, harm databases {ch_share('harm-db', 'WITH-AI'):.0f}% "
      f"WITH-AI, research {ch_share('research/other', 'ON-AI'):.0f}% ON-AI** (n = {len(F):,} frame records)", "",
      "Frame records by disclosure channel, percentages within the channel; *enter the frame* is the share of all the channel's records that got any "
      "adversary population. Figure 1 Panel B omits BOTH, so its channel n are "
      + ", ".join(f"{ch_frame[ch]['ON-AI'] + ch_frame[ch]['WITH-AI']:,}" for ch in CHANNELS) + f" (title n = {len(ON) + len(WI):,}) against the n below.", "",
      "| channel | channel records | enter the frame | ON-AI | WITH-AI | BOTH | ON-AI % with BOTH left out (Fig. 1B) |", "|---|---|---|---|---|---|---|"]
for ch in CHANNELS:
    tot = sum(source_class(r) == ch for r in C.values()); c = ch_frame[ch]; n = sum(c.values())
    L.append(f"| {ch} | {tot:,} | {n:,} ({pct(n, tot)}%) | " + " | ".join(f"{c[p]:,} ({pct(c[p], n)}%)" for p in ("ON-AI", "WITH-AI", "BOTH"))
             + f" | {pct(c['ON-AI'], c['ON-AI'] + c['WITH-AI'])}% |")

# ---- 2.3 frame, 2.4 rules
L += ["", "## How big are the two populations, and how were records assigned?"]
L += table(f"How big are the two populations? Near-equal in the frame (ON-AI {pct(len(ON), len(F))}%, WITH-AI {pct(len(WI), len(F))}%), but that ratio is a ratio of channels",
           F, lambda r: S[r["id"]]["population"], ci=True, num="2.3",
           desc=f"The same assignment restricted to the {len(F):,} frame records. Read Table 2.2 first: each channel contributes almost one population, "
                "so this ratio follows from the channel mix of the corpus.")
rc = collections.Counter(S[r["id"]]["rule"] for r in F); grp = {"corpus vector": rc["on-vector"] + rc["with-vector"], "text pattern": rc["on-vocabulary"] + rc["with-vocabulary"]}
L += table(f"How were records assigned? Corpus vector {pct(grp['corpus vector'], len(F))}%, text pattern {pct(grp['text pattern'], len(F))}%, conventional exploit "
           f"{pct(rc['conventional-exploit-of-ai-tooling'], len(F))}%", F, lambda r: S[r["id"]]["rule"], num="2.4",
           desc="One rule per record, in the order the script applies them: a vulnerability disclosure with no ON or WITH signal is NONE; `on-vector` / `with-vector` "
                "fire on the corpus attack vector, `on-vocabulary` / `with-vocabulary` on the text patterns, `conventional-exploit-of-ai-tooling` on an attacker word "
                "plus a conventional code vector (rce, ssrf, …). Vector lists and patterns are in `s02_split.py`.", col="rule")

# ---- 2.5 known weak spots
w_cve = [r for r in WI if source_class(r) == "cve/ghsa"]
w_code = [r for r in WI if vec(r) in CODE_VEC and not has_cve(r)]
avid = [r for r in ON if source_class(r) == "harm-db" and is_avid(r)]
hd_noavid = collections.Counter(S[r["id"]]["population"] for r in F if source_class(r) == "harm-db" and not is_avid(r))
conv = [r for r in ON if S[r["id"]]["rule"] == "conventional-exploit-of-ai-tooling"]
on_vd = [r for r in ON if r["category"] == "vulnerability-disclosure"]
wv = [r for r in WI if S[r["id"]]["rule"] == "with-vector"]; wv_na = [r for r in wv if not ADV.search(text(r))]
tagged = sum(any(re.search(r"malicious|intentional", t) for t in r["tags"]) for r in wv_na)
ov = [r for r in ON if S[r["id"]]["rule"] == "on-vector"]; ov_nn = [r for r in ov if not ADV.search(text(r)) and not ON_KW.search(text(r))]
none_att = [r for r in NO if r["id"] in J and J[r["id"]]["gold_labels"] and any(e in ATTACKER_ENTRIES for e in J[r["id"]]["gold_labels"])]
none_hand = [r for r in NO if r["id"] in J and J[r["id"]]["gold_labels"] is not None]
words = lambda r: {m.group(0).lower() for m in ADV.finditer(text(r))}
un_scam = [r for r in UN if words(r) & {"scam", "fraud"} and AI_INSTR.search(text(r))]
ex = lambda rs: min(r["id"] for r in rs)
L += ["", "## Where is the split known to be weak?", "",
      f"**Table 2.5. Where the split is known to be weak: {len(w_cve)} CVE rows in WITH-AI, {len(wv_na):,} WITH-AI rows resting on the vector alone, "
      f"{len(on_vd)} ON-AI rows with no observed attack** (one row per known weak spot)", "",
      "Each row is a group the rules place with less support than the rest; % is of the group's own population. The hand-labelled column gives the verdicts of the "
      "person who hand-labelled a subset of these records (Table 1.14), as names; it says what those rows are, not how common the problem is.", "",
      "| group | rows | % of its population | hand-labelled rows: verdicts | example id |", "|---|---|---|---|---|"]
rows25 = [
    (f"WITH-AI records from the CVE/GHSA channel (vectors {members(collections.Counter(vec(r) for r in w_cve).most_common(2))}): conventional CVEs the corpus "
     "vectored as deepfake or phishing; exclude before coding", w_cve, WI),
    (f"WITH-AI records with a conventional code vector ({members(collections.Counter(vec(r) for r in w_code).most_common(3))}) and no CVE or CWE: harm-database "
     "stories the corpus mis-vectored, placed by the text pattern", w_code, WI),
    (f"ON-AI harm-db records from AVID (record types {members(collections.Counter(r['category'] for r in avid).most_common())}); "
     f"without AVID the harm-db channel is {100*hd_noavid['WITH-AI']/sum(hd_noavid.values()):.0f}% WITH-AI / "
     f"{100*hd_noavid['ON-AI']/sum(hd_noavid.values()):.0f}% ON-AI", avid, ON),
    (f"ON-AI by the conventional-exploit rule (attacker word + code vector; {sum(bool(r.get('cve_ids')) for r in conv)} carry a CVE): the AI is the product "
     "attacked, not the mechanism", conv, ON),
    (f"ON-AI vulnerability disclosures: no attack observed (`exploited_in_wild` set on {sum(r.get('exploited_in_wild') is True for r in on_vd)}; corpus-wide "
     f"{sum(r.get('exploited_in_wild') is True for r in C.values())})", on_vd, ON),
    (f"with-vector WITH-AI records with no attacker word in the searched text ({by_channel(wv_na, lambda r: True)}; {sum(bool(WITH_KW.search(text(r))) for r in wv_na)} "
     f"match the WITH text pattern; {tagged} carry a corpus tag naming malicious or intentional use that the rules do not read)", wv_na, WI),
    (f"on-vector ON-AI records matching neither the attacker nor the ON text pattern (vectors {members(collections.Counter(vec(r) for r in ov_nn).most_common(3))}); "
     f"{sum(bool(FAIR.search(text(r))) for r in ov_nn)} are bias or fairness evaluations by their wording", ov_nn, ON),
    (f"NONE records the person filed under {', '.join(name(e) for e in ATTACKER_ENTRIES)} ({members(collections.Counter(S[r['id']]['rule'] for r in none_att).most_common())}): "
     f"attacker records the rules missed; % is of the {len(none_hand)} hand-labelled NONE records", none_att, none_hand),
    (f"UNRESOLVED 'scam' / 'fraud' records containing an AI-instrument phrase (AI-generated, voice clone, chatbot, …): WITH-AI in substance", un_scam, UN)]
for g, rs, popn in rows25: L.append(f"| {g} | {len(rs):,} | {pct(len(rs), len(popn))} | {hand(rs)} | {ex(rs)} |")

# ---- 2.6–2.9 vector and record type per population
def pooled_line(rs, key, top):
    c = collections.Counter(key(r) for r in rs); rest = c.most_common()[top:]
    return ["", f"*Pooled row members:* {members(rest)}."] if rest else []
on_code = collections.Counter(vec(r) for r in ON if vec(r) in CODE_VEC); on_vec = collections.Counter(vec(r) for r in ON)
L += ["", "## ON-AI: what does the corpus say about these records?"]
L += table(f"ON-AI by corpus attack vector: prompt injection first ({pct(on_vec['prompt-injection'], len(ON))}%), then a long tail of conventional exploits", ON, vec, num="2.6",
           desc=f"One value per record; `other` is the corpus's own value. Conventional code vectors ({members(on_code.most_common(4))}, …) are "
                f"{sum(on_code.values())} records ({pct(sum(on_code.values()), len(ON))}%).", col="attack vector")
L += pooled_line(ON, vec, 12)
vd_rule = collections.Counter(S[r["id"]]["rule"] for r in on_vd)
L += table(f"{share_word(len(on_vd), len(ON)).capitalize()} ON-AI records are vulnerability disclosures, not observed attacks", ON, lambda r: r["category"], num="2.7",
           desc=f"The corpus record type. The {len(on_vd)} disclosures enter ON-AI through the vector ({vd_rule['on-vector']}) or the text pattern ({vd_rule['on-vocabulary']}), "
                f"not because an attack was observed; {sum(source_class(r) == 'cve/ghsa' for r in on_vd)} are cve/ghsa and {sum(is_avid(r) for r in on_vd)} are AVID.", col="record type")
w_vec = collections.Counter(vec(r) for r in WI); rce = [r for r in WI if vec(r) == "rce"]
hdb = lambda v: f"{sum(source_class(r) == 'harm-db' for r in WI if vec(r) == v)} of {w_vec[v]}"  # harm-db share of a WITH-AI vector
df = [r for r in WI if vec(r) == "deepfake"]; df_na = [r for r in df if not ADV.search(text(r))]
wc = lambda p: sum(bool(re.search(p, text(r), re.I)) for r in df_na)
L += ["", "## WITH-AI: what does the corpus say about these records?"]
L += table(f"WITH-AI is {pct(w_vec['deepfake'], len(WI))}% deepfake; its rce, data-exfiltration and malware rows are corpus mislabels on harm-database stories", WI, vec, num="2.8",
           desc=f"The {len(rce)} rce rows are harm-database stories ({hdb('rce')}; {sum(has_cve(r) for r in rce) or 'none'} carry a CVE or CWE) placed by the WITH text pattern; "
                f"data-exfiltration ({hdb('data-exfiltration')}) and malware ({hdb('malware')}) are harm-db too. {len(df_na)} of the {len(df):,} deepfake rows contain no attacker word; {sum(bool(STUB.search(text(r))) for r in df_na)} "
                f"of those are tracker template entries ({members(collections.Counter(STUB.search(text(r)).group(0) for r in df_na if STUB.search(text(r))).most_common())}) whose text is a "
                f"headline plus boilerplate, naming the harm ('sexual' / 'nonconsensual' / 'explicit' / 'nude' on {wc(r'sexual|non-?consensual|explicit|nude')}) rather than an actor.", col="attack vector")
L += pooled_line(WI, vec, 12)
w_vd = [r for r in WI if r["category"] == "vulnerability-disclosure"]
L += table(f"WITH-AI is {pct(sum(r['category'] == 'real-world' for r in WI), len(WI))}% real-world incidents; the {len(w_vd)} vulnerability disclosures are conventional CVEs to exclude",
           WI, lambda r: r["category"], num="2.9",
           desc=f"The corpus record type. The vulnerability disclosures are Table 2.5 row 1 ({sum(source_class(r) == 'cve/ghsa' for r in w_vd)} of {len(w_vd)} are cve/ghsa): "
                "CVE/GHSA records the corpus vectored as deepfake or phishing.", col="record type")

# ---- 2.10 date precision, 2.11 year
prec = lambda r: {10: "day", 7: "month", 4: "year-only"}.get(len(str(r["date"])), "other")
pc = {p: collections.Counter(prec(r) for r in rs) for p, rs in (("ON-AI", ON), ("WITH-AI", WI))}
L += ["", "## When are the records dated, and how precisely?", "",
      f"**Table 2.10. Date precision by population and channel: ON-AI {pct(pc['ON-AI']['month'], len(ON))}% month-only, WITH-AI {pct(pc['WITH-AI']['day'], len(WI))}% day-level** "
      f"(ON-AI n = {len(ON):,}; WITH-AI n = {len(WI):,})", "",
      "Precision of the corpus `date` field (YYYY-MM-DD, YYYY-MM or YYYY) within population and channel. The two populations cannot be placed on a common time axis "
      "finer than a year.", "", "| population | channel | n | day % | month % | year-only % |", "|---|---|---|---|---|---|"]
for p, rs in (("ON-AI", ON), ("WITH-AI", WI)):
    for ch in CHANNELS + ("all channels",):
        sub = [r for r in rs if ch == "all channels" or source_class(r) == ch]; c = collections.Counter(prec(r) for r in sub)
        if sub: L.append(f"| {p} | {ch} | {len(sub):,} | {pct(c['day'], len(sub))} | {pct(c['month'], len(sub))} | {pct(c['year-only'], len(sub))} |")
oor = [r for r in F if not 2020 <= r["year"] <= 2026]; y26 = sum(r["year"] == 2026 for r in F); on26 = collections.Counter(source_class(r) for r in ON if r["year"] == 2026)
L += ["", f"**Table 2.11. Record year in the frame: {share_word(y26, len(F))} of the rows ({y26:,} of {len(F):,}) are dated 2026** (counts; reflects when each tracker was ingested, Table 1.5)", "",
      f"Frame records per record year, 2020–2026, with a total row; the {len(oor)} frame records outside the range are dated {min(r['year'] for r in oor)}–{max(r['year'] for r in oor)} "
      f"({members(collections.Counter(S[r['id']]['population'] for r in oor).most_common())}) and none is dated after {max(r['year'] for r in F)}. "
      + (f"ON-AI passes WITH-AI in 2025–26 because the CVE feed is the channel still being fed (Table 1.6): {on26['cve/ghsa']} of the {sum(on26.values())} ON-AI records dated 2026 are cve/ghsa." if on26['cve/ghsa'] > sum(on26.values()) / 2 else ""), "",
      "| year | ON-AI | WITH-AI | BOTH | frame |", "|---|---|---|---|---|"]
for y in list(range(2020, 2027)) + ["total 2020–2026"]:
    sub = [r for r in F if (2020 <= r["year"] <= 2026 if y == "total 2020–2026" else r["year"] == y)]; c = collections.Counter(S[r["id"]]["population"] for r in sub)
    L.append(f"| {y} | {c['ON-AI']:,} | {c['WITH-AI']:,} | {c['BOTH']:,} | {len(sub):,} |")

# ---- 2.12 UNRESOLVED
uw = collections.Counter(w for r in UN for w in words(r)); single = sum(len(words(r)) == 1 for r in UN)
u_ch, u_cat, u_vec = (collections.Counter(f(r) for r in UN) for f in (source_class, lambda r: r["category"], vec))
subsets = [("AI detects, flags or blocks fraud (operator or user harm, not an attacker's instrument)", [r for r in UN if words(r) & {"fraud", "scam"} and FRAUD_DET.search(text(r))]),
           ("'campaign' is an advertising or marketing campaign", [r for r in UN if "campaign" in words(r) and AD_CAMP.search(text(r))]),
           ("'scam' / 'fraud' with an AI-instrument phrase (WITH-AI in substance; Table 2.5 last row)", un_scam)]
L += ["", "## Why are records UNRESOLVED?", "",
      f"**Table 2.12. Why {len(UN)} records are UNRESOLVED: 'fraud', 'scam' or 'campaign' appears but nothing says what the AI did** (n = {len(UN)} records)", "",
      f"Records containing each attacker word (a record can contain several, so % need not sum to 100; {single} contain exactly one). "
      f"{u_ch['harm-db']} are harm-db, {u_cat['real-world']} real-world, {u_vec['other']} carry vector `other`; {hand(UN, 4).split(':')[0]} are hand-labelled "
      f"({hand(UN, 4).split(': ')[1]}).", "",
      "| attacker word | records | % of UNRESOLVED |", "|---|---|---|"]
for w, n in uw.most_common(8): L.append(f"| {w} | {n} | {pct(n, len(UN))} |")
rest = sum(n for _, n in uw.most_common()[8:])
if rest: L.append(f"| *{len(uw) - 8} more words (pooled)* | {rest} | {pct(rest, len(UN))} |")
L += ["", f"**Table 2.12b. Three UNRESOLVED subsets a reader can settle from the text alone: {', '.join(str(len(rs)) for _, rs in subsets)} records** (n = {len(UN)} UNRESOLVED records)", "",
      "Diagnostic patterns in `s02_split.py` that assign nothing; each row is a subset of Table 2.12 with the verdicts of the person who hand-labelled some of them.", "",
      "| subset | records | hand-labelled rows: verdicts | example id |", "|---|---|---|---|"]
for g, rs in subsets: L.append(f"| {g} | {len(rs)} | {hand(rs)} | {ex(rs) if rs else '—'} |")

# ---- 2.13 independent check
L += ["", "## Does an independent person's label agree with the split?", "",
      f"**Table 2.13. Does an independent person's label agree with the split? Hand labels land on different entries per population** (n = {len(C):,} records)", "",
      "Per population: records with a rank-validation classifier label, records hand-labelled by the one person who labelled for that project, those judged to fit no entry, and the "
      "entries used most, as names (rank-validation's numbering differs from the corpus's, Table 1.0). The hand-labelled rows were drawn by the quota in Table 1.14, so "
      "use this for *where* each population's records land, never for how common an entry is.", "",
      "| population | records | with a classifier label | hand-labelled | no entry fits | distinct entries used | five most used entries |", "|---|---|---|---|---|---|---|"]
for p, rs in (("ON-AI", ON), ("WITH-AI", WI), ("BOTH", BO), ("UNRESOLVED", UN), ("NONE", NO)):
    lab = [r for r in rs if r["id"] in J]; g = [J[r["id"]]["gold_labels"] for r in lab if J[r["id"]]["gold_labels"] is not None]
    oos = sum(x == [] for x in g); c = collections.Counter(name(e) for x in g for e in x)
    L.append(f"| {p} | {len(rs):,} | {len(lab):,} ({pct(len(lab), len(rs))}%) | {len(g):,} ({pct(len(g), len(rs))}%) | {oos} ({pct(oos, len(g))}% of hand-labelled) | "
             f"{len(c)} | {members(c.most_common(5))} |")
write("s02_split.md", L)
