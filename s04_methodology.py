#!/usr/bin/env python3
"""s04_methodology.py — Step 4. Entry point, target, AI medium and objective for ON-AI and WITH-AI, after reclassifying the unstated records.
Per record and dimension the value is assigned in a fixed order, first hit wins: text rule (ENTRY/TARGET/AIROLE/OBJECTIVE, keyword patterns
over title+description+affected) → corpus-label fallback (FALLBACK, attack-vector label → value where unambiguous) → label-group rule
(RECLASS, a group of attack-vector labels or a tracker-stub description → value) → coded label (coded/relabels.json: two independent coders,
a third adjudicating) → 'other' (a safety net, asserted never to fire). The 'pre' value is the one after the first two steps, 'unstated' kept.
Outputs: out/methodology.json (id → post values, _pre, _how, dependency; s05 reads 'objective'), out/dataset_pre.csv, out/dataset_post.csv,
out/s04_methodology.md
"""
import collections, csv, json, re
from common import load_full, source_class, text, table, write, READ, ROOT, OUT, CHANNELS
S = json.load(open(OUT / "split.json")); C = load_full(); CODED = json.load(open(ROOT / "coded" / "relabels.json"))
RX = lambda p: re.compile(p, re.I)
def first(rules, t, default="unstated"):
    return next((name for name, rx in rules if rx.search(t)), default)
ENTRY = [("indirect carrier (web/email/doc/tool output)", RX(r"indirect|zero-?click|e-?mail|web ?page|website|\bdocuments?\b|calendar|retriev|\brag\b|markdown|issue comment|pull request|tool (result|output)|hidden (text|instruction)")),
         ("direct prompt by the user", RX(r"prompt injection|jailbr|system prompt|crafted prompt|user (prompt|input)|chat ?box")),
         ("malicious package / model / skill (supply chain)", RX(r"typosquat|malicious (package|pypi|npm|extension|skill|plugin|model)|backdoored|trojan|supply.chain")),
         ("stolen or leaked credential", RX(r"stolen|leaked (api )?key|credential|access token|valid account|hard-?coded")),
         ("exposed / misconfigured service", RX(r"unauthenticated|exposed|misconfigur|publicly accessible|without auth|default (password|credential)|shodan")),
         ("adversarial input to a classifier", RX(r"adversarial (example|input|patch|perturb)|evad|bypass(ed|ing)? (the )?(detect|filter|classifier)"))]
TARGET = [("agent / copilot / coding assistant / MCP", RX(r"\bagent|copilot|cursor|claude code|gemini cli|codex|mcp|openclaw|\bcline\b|windsurf|autogpt|crewai|langgraph|n8n|\bdify\b|flowise")),
          ("consumer chatbot / hosted LLM app", RX(r"chatgpt|\bgpt-?[345]|gemini\b|claude\b|bard|chatbot|assistant|character\.ai|grok|deepseek|(?<!o)llama")),
          ("ML/LLM framework or serving library", RX(r"langchain|llama.?index|vllm|ollama|mlflow|tensorflow|pytorch|transformers|comfyui|gradio|triton|sglang|\bray\b|kubeflow")),
          ("RAG / vector / memory store", RX(r"vector (db|database|store)|embedding|pinecone|weaviate|chroma|milvus|qdrant|memory")),
          ("model hub / training pipeline / weights", RX(r"hugging ?face|model hub|weights|checkpoint|fine-?tun|training (data|set|pipeline)|poison")),
          ("detection / classification model", RX(r"detector|classifier|spam|malware detect|facial[- ]recognition|fraud detect|content moderation"))]
CODE_FRAG = r"(ai|llm|chatgpt|model)[- ](generated|written|assisted|driven|produced) (scripts?|payloads?|code)|(generated|wrote|writing|produced) (a |the )?(malicious )?(scripts?|payloads?)"
AIROLE = [("synthetic audio/voice", RX(r"voice ?clon|audio deepfake|synthetic (voice|audio)|robocall|voice (of|imperson)")),
          ("synthetic video", RX(r"deepfake video|video call|synthetic video|face.?swap|live deepfake")),
          ("synthetic image", RX(r"image|photo|nude|undress|explicit|csam|sexual")),
          ("generated text (phishing / lures / disinformation)", RX(r"phish|lure|chat ?bot|generated (text|message|email)|disinformation|propaganda|fake (news|review|article)|influence operation")),
          ("generated or assisted code (malware / tooling)", RX(r"malware|ransomware|exploit (code|generation)|wrote (the )?code|coding|" + CODE_FRAG)),
          ("reconnaissance / planning / orchestration", RX(r"reconnaissance|planning|orchestrat|autonomous|agentic|automated (attack|campaign)|vulnerability research"))]
OBJECTIVE = [("financial fraud / extortion", RX(r"fraud|scam|extort|sextort|ransom|money|payment|transfer|\$\d|million|\binvest(ments?|ors?|ing|ed|s)?\b|crypto|bank")),
             ("political / influence", RX(r"election|political|candidate|president|minister|(?<!third[- ])(?<!http)\bparty\b|vote|propaganda|influence")),
             ("non-consensual / abuse imagery", RX(r"non-?consensual|nude|undress|explicit|csam|sexual|revenge")),
             ("defamation / impersonation of a person", RX(r"impersonat|defam|fake (statement|video of|audio of)|celebrity|ceo|executive")),
             ("intrusion / cyber operation", RX(r"intrusion|breach|hack|credential|network|espionage|\bapt\d*\b|threat actor"))]
DIMS = {"entry_point": ENTRY, "target": TARGET, "ai_role": AIROLE, "objective": OBJECTIVE}
DIM4 = tuple(DIMS); NAME = {"entry_point": "entry point", "target": "target", "ai_role": "AI medium", "objective": "objective"}; PLURAL = {"entry_point": "entry points", "target": "targets", "ai_role": "AI media", "objective": "objectives"}
NUM = {"entry_point": "4.1", "target": "4.2", "ai_role": "4.4", "objective": "4.5"}
# Second tier: corpus attack-vector label → value, only where the mapping is unambiguous. Two values exist only here (and in the codebook),
# because the label says less than the text rules ask: a prompt-injection label does not say whether the prompt was the user's own or carried
# in content, and a deepfake label does not say image, voice or video. The target has no fallback: the label names no component.
PI_LABEL, DK_LABEL = "prompt injection, carrier not stated", "deepfake, medium not stated"
FALLBACK = {"entry_point": {"malware": ENTRY[2][0], "supply-chain": ENTRY[2][0], "backdoor": ENTRY[2][0], "adversarial-input": ENTRY[5][0], "evasion": ENTRY[5][0],
                            "indirect-prompt-injection": ENTRY[0][0], "prompt-injection": PI_LABEL, "jailbreak": PI_LABEL},
            "target": {}, "ai_role": {"csam-generation": AIROLE[2][0], "deepfake": DK_LABEL}, "objective": {"csam-generation": OBJECTIVE[2][0]}}
# Third tier: label-group rules. A group of attack-vector labels (or, for the target, a tracker-stub description) fixes the value.
CONV = {"auth-bypass", "command-injection", "csrf", "data-exfiltration", "deserialization", "dos", "info-disclosure", "path-traversal", "rce", "sql-injection", "ssrf", "xss"}
AGENT = {"agent-hijack", "memory-poisoning", "sandbox-escape", "tool-abuse"}; POISON = {"model-poisoning", "data-poisoning"}
INFER = {"membership-inference", "model-extraction", "model-inversion"}; MALPKG = {"backdoor", "malware", "supply-chain"}
GNAME = {"conventional-exploit": CONV, "agent": AGENT, "poisoning": POISON, "inference": INFER, "malicious-package": MALPKG}
RECLASS = {"entry_point": [(("conventional-exploit",), "exploit of a conventional software vulnerability"), (("agent",), "via the agent's tools or sandbox"),
                           (("poisoning",), "poisoned training data or model"), (("inference",), "query access to the model (extraction / inference)")],
           "target": [], "ai_role": [(("conventional-exploit", "malicious-package"), "none: conventional exploit record misplaced in WITH-AI")], "objective": []}
STUB = ("Tracked by the OECD", "AI Incident Database (AIID) entry", "AIAAIC-tracked incident"); T_STUB = "other (tracker stub, no system named)"
def reclass(r, dim):
    if dim == "target": return T_STUB if r["description"].startswith(STUB) else None
    return next((v for gs, v in RECLASS[dim] if any(r["attack_vector"] in GNAME[g] for g in gs)), None)
HOW = ("text rule", "corpus label", "label-group rule", "coded from text", "other")
def assign(r, dim):
    """(value, how, coder record or None); the pre value is the value when how is one of the first two, else 'unstated'."""
    v = first(DIMS[dim], text(r), None)
    if v: return v, HOW[0], None
    v = FALLBACK[dim].get(r["attack_vector"])
    if v: return v, HOW[1], None
    v = reclass(r, dim)
    if v: return v, HOW[2], None
    c = CODED["labels"][dim].get(r["id"])
    if c: return c["final"], HOW[3], c
    return "other", HOW[4], None
MODEL_VEC = ("prompt-injection", "indirect-prompt-injection", "jailbreak", "adversarial-input", "evasion", "model-extraction", "membership-inference", "model-inversion")
def dep(r):
    if r.get("cve_ids") or r.get("cwe_ids"): return "CVE/CWE present (software vulnerability)"
    if r["attack_vector"] in MODEL_VEC: return "model-level attack vector, no CVE/CWE"
    return "unstated"
ON = [C[i] for i, s in S.items() if s["population"] == "ON-AI"]; WI = [C[i] for i, s in S.items() if s["population"] == "WITH-AI"]
POPS = (("ON-AI", ON), ("WITH-AI", WI)); ASK = {"ON-AI": ("entry_point", "target"), "WITH-AI": ("ai_role", "objective")}
POP = {"entry_point": ON, "target": ON, "ai_role": WI, "objective": WI}

# ---------------------------------------------------------------- assignment
M, NOTE, used = {}, {}, collections.defaultdict(set)
for pop, rows in POPS:
    for r in rows:
        m, notes = {"dependency": dep(r)}, []
        for d in ASK[pop]:
            v, how, c = assign(r, d)
            m[d], m[d + "_how"], m[d + "_pre"] = v, how, (v if how in HOW[:2] else "unstated")
            if c: used[d].add(r["id"]); notes += [f"{d}: {c['note']}"] if c["note"] else []
        M[r["id"]] = m; NOTE[r["id"]] = "; ".join(notes)
left = {d: sum(M[r["id"]][d + "_how"] == HOW[4] for r in POP[d]) for d in DIM4}
print("still unstated after the coded labels, set to 'other':", left); assert not any(left.values()), left  # the count is printed before the assert
assert all(used[d] == set(CODED["labels"][d]) for d in DIM4), {d: (len(used[d]), len(CODED["labels"][d])) for d in DIM4}  # the coded file covers exactly what the rules leave
assert all(c["final"] != "unstated" for d in DIM4 for c in CODED["labels"][d].values())
assert {source_class(r) for r in ON if r.get("cve_ids") or r.get("cwe_ids")} == {"cve/ghsa"}
json.dump(M, open(OUT / "methodology.json", "w"), indent=0); print(f"wrote out/methodology.json ({len(M):,} records)")

# ---------------------------------------------------------------- datasets
IDENT = ["id", "population", "channel", "year", "record_type", "attack_vector", "cve_ids", "title", "affected", "description"]
ident = lambda r, pop: [r["id"], pop, source_class(r), r["year"], r.get("category", ""), r.get("attack_vector", ""), ";".join(r.get("cve_ids") or []), r["title"], r.get("affected") or "", r["description"]]
g = lambda r, k: M[r["id"]].get(k, "")
pre_src = lambda r, d: (lambda h: h if h in HOW[:2] else "unstated")(g(r, d + "_how")) if d in M[r["id"]] else ""
def dataset(name, header, row):
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(header); n = 0
        for pop, rows in POPS:
            for r in rows: w.writerow(ident(r, pop) + row(r)); n += 1
    print(f"wrote out/{name} ({n:,} rows)")
dataset("dataset_pre.csv", IDENT + [x for d in DIM4[:2] for x in (d, d + "_source")] + ["dependency"] + [x for d in DIM4[2:] for x in (d, d + "_source")],
        lambda r: [x for d in DIM4[:2] for x in (g(r, d + "_pre"), pre_src(r, d))] + [g(r, "dependency")] + [x for d in DIM4[2:] for x in (g(r, d + "_pre"), pre_src(r, d))])
post3 = lambda r, d: [g(r, d + "_pre"), g(r, d), g(r, d + "_how")]
dataset("dataset_post.csv", IDENT + [f"{d}_{x}" for d in DIM4[:2] for x in ("pre", "post", "how")] + ["dependency"] + [f"{d}_{x}" for d in DIM4[2:] for x in ("pre", "post", "how")] + ["coded_note"],
        lambda r: [x for d in DIM4[:2] for x in post3(r, d)] + [g(r, "dependency")] + [x for d in DIM4[2:] for x in post3(r, d)] + [NOTE[r["id"]]])

# ---------------------------------------------------------------- markdown
pct = lambda a, b: f"{100*a/b:.1f}" if b else "—"
ch = lambda rows: collections.Counter(source_class(r) for r in rows)
val = lambda dim: (lambda r: M[r["id"]][dim])
NO_ATT = "no attacker: operator harm or model failure (misplaced record)"; NONE_W = RECLASS["ai_role"][0][1]
# Residue values: the dimension does not fit the record. Kept as rows, counted in Table 4.0's last column and in each table's title.
res_kind = lambda v: "'other'" if v == "other" or v.startswith("other (") else "'no attacker'" if v.startswith("no attacker") else "'none'" if v.startswith("none:") else None
res_phrase = lambda vals: (lambda k: " or ".join([", ".join(k[:-1]), k[-1]]) if len(k) > 1 else k[0])([x for x in ("'other'", "'no attacker'", "'none'") if x in {res_kind(v) for v in vals}])
AG = CODED["meta"]["agreement"]
fb_clause = lambda d: "; ".join(f"{', '.join(k for k, x in FALLBACK[d].items() if x == v)} → {v} ({NAME[d]})" for v in dict.fromkeys(FALLBACK[d].values()))
seen = set()
def gname(g):      # a group's labels are spelled out the first time the group is named, then only its name is used
    s = f"{g} ({', '.join(sorted(GNAME[g]))})" if g not in seen else g; seen.add(g); return s
rc_clause = lambda d: "; ".join(f"{' or '.join(gname(g) for g in gs)} → {v} ({NAME[d]})" for gs, v in RECLASS[d])
chan_n = lambda P: ", ".join(f"{x} {ch(P)[x]:,}" for x in CHANNELS)
L = ["# Step 4 — Entry point, target, AI medium and objective, after reclassifying the unstated records", "",
     "Each ON-AI record gets an entry point (Table 4.1) and a target (4.2), each WITH-AI record an AI medium (4.4) and an attacker objective (4.5), assigned in a fixed order, first hit wins: "
     "a text rule (ordered keyword patterns over title + description + affected: the lists ENTRY, TARGET, AIROLE and OBJECTIVE in `s04_methodology.py`), "
     "else the corpus attack-vector label where that label maps to exactly one value of the dimension being assigned, "
     "else a label-group rule (a group of attack-vector labels fixes the value; for the target, which no label names, the rule at this step is instead a description-prefix test for tracker stubs, placed after the keyword rules so that a system named in the text wins), "
     f"else a label coded from the text, which may be 'other' or 'no attacker …'; a final 'other' safety net fired {sum(left.values())} times (the script stops if it fires). "
     f"The corpus-label fallback: {'; '.join(fb_clause(d) for d in DIM4 if FALLBACK[d])}. "
     f"The label-group rules, each group's labels listed once: {'; '.join(rc_clause(d) for d in DIM4 if RECLASS[d])}; a description starting "
     + " or ".join(f"'{s}'" for s in STUB) + f" → {T_STUB} (target). "
     f"The coded labels live in `coded/relabels.json` (per dimension, id → final, the two coders' labels, an adjudicated flag and a note; `meta.codebook` is the value menu the coders chose from, `meta.agreement` the counts below), made by {CODED['meta']['coders']}; coders agreed on "
     + ", ".join(f"{AG[d]['coders_agreed']} of {AG[d]['records']} {PLURAL[d]}" for d in DIM4) + f", {sum(AG[d]['unresolved_set_to_other'] for d in DIM4)} unresolved, "
     "and the script checks that the file covers exactly the records the three rules leave unstated and that no final label is 'unstated'. "
     f"Four values mark records the dimension does not fit and stay visible as rows: '{NO_ATT}' = harm with no adversary described, so the record belongs in neither population; "
     f"'{NONE_W}' = the attack-vector label is a conventional exploit or a malicious package, so no AI medium is involved and the record is in the wrong population; "
     f"'{T_STUB}' = a pointer to an external tracker that names no system; 'other' = an attack the coders could not fit to any codebook value; "
     "every such record keeps its population and value into step 5 (which reads `objective` from `out/methodology.json`); none is moved or dropped. "
     "`out/dataset_pre.csv` holds every ON-AI and WITH-AI record with the values after the first two steps ('unstated' kept) and `out/dataset_post.csv` the pre and post values: "
     "the dimension columns are `entry_point`, `target`, `ai_role` (= AI medium) and `objective`, empty when the dimension is not asked of the record's population, "
     "in pre as `<dim>` and `<dim>_source` (text rule / corpus label / unstated), in post as `<dim>_pre`, `<dim>_post` and `<dim>_how` plus `coded_note` ('dimension: reason' from the coders, filled only where how is 'coded from text'), "
     "and `dependency` holds Table 4.3's value for every record of both populations; both files and `out/methodology.json` are written by `s04_methodology.py` (`make s04`), never by hand; "
     f"records entered the populations by step 2's rules (Table 2.4), and by channel ON-AI has {chan_n(ON)} records and WITH-AI {chan_n(WI)} "
     f"(channel columns are % of that channel, so each {100/ch(WI)['research/other']:.1f} in WITH-AI's research/other column is one record).", "", READ, "",
     f"**Table 4.0. How each value was assigned** (ON-AI n = {len(ON):,}; WITH-AI n = {len(WI):,})", "",
     "Counts of records per dimension by the step that fixed the value (the four step columns sum to the records); the last column counts records holding one of the four residue values defined above, whichever step set them. In the notes of Tables 4.1–4.5, 'rule' = label-group rule, 'coded' = coded from text, and * marks a value that did not exist before this step.", "",
     "| dimension (table) | records | text rule | corpus label | label-group rule | coded from text (coders agreed / adjudicated) | value 'other', 'no attacker' or 'none' |", "|---|---|---|---|---|---|---|"]
T0 = {}
for d in DIM4:
    P = POP[d]; hc = collections.Counter(M[r["id"]][d + "_how"] for r in P); cs = [CODED["labels"][d][r["id"]] for r in P if M[r["id"]][d + "_how"] == HOW[3]]
    adj = sum(c["adjudicated"] for c in cs); oth = sum(bool(res_kind(M[r["id"]][d])) for r in P); cell = lambda a: f"{a:,} ({pct(a, len(P))}%)"
    T0[d] = (len(P), hc[HOW[0]], hc[HOW[1]], hc[HOW[2]], len(cs), len(cs) - adj, adj, oth)
    L.append(f"| {'ON-AI' if P is ON else 'WITH-AI'} {NAME[d]} ({NUM[d]}) | {len(P):,} | {cell(hc[HOW[0]])} | {cell(hc[HOW[1]])} | {cell(hc[HOW[2]])} | {cell(len(cs))} ({len(cs) - adj} / {adj}) | {cell(oth)} |")
SHORT = {HOW[2]: "rule", HOW[3]: "coded"}
def post_table(d, question):
    P = POP[d]; c = collections.Counter(M[r["id"]][d] for r in P); top, tn = c.most_common(1)[0]; oth = sum(bool(res_kind(v)) for v in c.elements())
    un = [r for r in P if M[r["id"]][d + "_pre"] == "unstated"]; cu = collections.Counter(M[r["id"]][d] for r in un)
    hows = {v: collections.Counter(M[r["id"]][d + "_how"] for r in un if M[r["id"]][d] == v) for v in cu}
    how_s = lambda v: ", ".join(f"{SHORT[h]} {n}" for h, n in hows[v].most_common()) if len(hows[v]) > 1 else SHORT[hows[v].most_common(1)[0][0]]
    known = {n for n, _ in DIMS[d]} | set(FALLBACK[d].values())
    desc = (f"Before reclassification {len(un):,} records ({pct(len(un), len(P))}%) were unstated; they now hold, largest first: "
            + "; ".join(f"{v}{'' if v in known else '*'} {n} ({how_s(v)})" for v, n in cu.most_common())
            + ".")
    return table(f"{'ON-AI' if P is ON else 'WITH-AI'}: {question} {top} {pct(tn, len(P))}%; {pct(oth, len(P))}% {res_phrase(c)}",
                 P, val(d), ci=True, channels=True, num=NUM[d], top=len(c), rest=False, desc=desc)
L += post_table("entry_point", "how did the adversary first reach the AI system?")
L += post_table("target", "which part of the AI stack was attacked?")
CVE, MV = "CVE/CWE present (software vulnerability)", "model-level attack vector, no CVE/CWE"; dc = collections.Counter(dep(r) for r in ON)
both_dep = sum(bool(r.get("cve_ids") or r.get("cwe_ids")) and r["attack_vector"] in MODEL_VEC for r in ON)
L += table(f"ON-AI: does the record carry a CVE/CWE ({100*dc[CVE]/len(ON):.0f}%), a model-level attack vector ({100*dc[MV]/len(ON):.0f}%) or neither ({100*dc['unstated']/len(ON):.0f}%)?", ON, dep, ci=True, num="4.3",
           desc=f"Read off corpus fields, unchanged by the reclassification: a CVE or CWE id, else one of the {len(MODEL_VEC)} model-level attack-vector labels ({', '.join(MODEL_VEC)}), else unstated. "
                f"No channel columns because every CVE/CWE record is cve/ghsa; {both_dep} records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor.")
L += post_table("ai_role", "what did the AI generate: image, voice, text, video or code?")
L += post_table("objective", "what was the attacker after?")
write("s04_methodology.md", L)
