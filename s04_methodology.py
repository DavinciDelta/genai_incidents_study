#!/usr/bin/env python3
"""s04_methodology.py — Step 4. Entry point, target, AI medium and objective for ON-AI and WITH-AI: the reviewed (cleaned) labels.
Per record and dimension a first value is assigned in a fixed order, first hit wins: text rule (ENTRY/TARGET/AIROLE/OBJECTIVE, keyword patterns
over title+description+affected) → corpus-label fallback (FALLBACK, attack-vector label → value where unambiguous) → label-group rule
(RECLASS, a group of attack-vector labels or a tracker-stub description → value) → coded label (coded/relabels.json: two independent coders,
a third adjudicating) → 'other' (a safety net, asserted never to fire). The review of every label (coded/review.json) then replaces the
values two reviewers or the adjudicator rejected. The md reports only the reviewed values; step 6 compares them with the first keyword
values ('pre': the value after the first two steps, 'unstated' kept), which this script also writes.
Outputs: out/methodology.json (id → reviewed values, _pre, _how, _match (words a text rule matched), dependency; s05 reads it to clean its
populations), out/dataset_pre.csv, out/dataset_post.csv, out/dataset_post_2026.csv, out/s04_methodology.md
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
HOW = ("text rule", "corpus label", "label-group rule", "coded from text", "other", "corrected by review")
REVIEW = json.load(open(ROOT / "coded" / "review.json")) if (ROOT / "coded" / "review.json").exists() else None   # label review: sample verdicts + corrections
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
            if how == HOW[0]: m[d + "_match"] = next(h.group(0) for _, rx in DIMS[d] if (h := rx.search(text(r))))   # the words the winning text rule matched (step 6 quotes them)
            if c: used[d].add(r["id"]); notes += [f"{d}: {c['note']}"] if c["note"] else []
        M[r["id"]] = m; NOTE[r["id"]] = "; ".join(notes)
if REVIEW:   # corrections from the two-reviewer sample audit override the rule value; the pre value and the audit trail stay
    for c in REVIEW["corrections"]:
        m = M[c["id"]]; assert m[c["dim"]] == c["from"], c
        m[c["dim"] + "_pre_how"] = m[c["dim"] + "_how"]   # the rule source stays with the pre value in dataset_pre.csv
        m[c["dim"]], m[c["dim"] + "_how"] = c["to"], HOW[5]; NOTE[c["id"]] = (NOTE[c["id"]] + "; " if NOTE[c["id"]] else "") + f"{c['dim']}: review: {c['note']}"
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
pre_src = lambda r, d: (lambda h: h if h in HOW[:2] else "unstated")(M[r["id"]].get(d + "_pre_how") or g(r, d + "_how")) if d in M[r["id"]] else ""
def dataset(name, header, row, keep=lambda r: True):
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(header); n = 0
        for pop, rows in POPS:
            for r in rows:
                if keep(r): w.writerow(ident(r, pop) + row(r)); n += 1
    print(f"wrote out/{name} ({n:,} rows)")
dataset("dataset_pre.csv", IDENT + [x for d in DIM4[:2] for x in (d, d + "_source")] + ["dependency"] + [x for d in DIM4[2:] for x in (d, d + "_source")],
        lambda r: [x for d in DIM4[:2] for x in (g(r, d + "_pre"), pre_src(r, d))] + [g(r, "dependency")] + [x for d in DIM4[2:] for x in (g(r, d + "_pre"), pre_src(r, d))])
RSTAT = REVIEW.get("verdicts", {}) if REVIEW else {}   # review status per label: confirmed / corrected / kept with dissent
rstat = lambda r, d: (RSTAT.get(f"{d}|{r['id']}", "not reviewed") if d in M[r["id"]] else "")
post3 = lambda r, d: [g(r, d + "_pre"), g(r, d), g(r, d + "_how"), rstat(r, d)]
POST_H = IDENT + [f"{d}_{x}" for d in DIM4[:2] for x in ("pre", "post", "how", "review")] + ["dependency"] + [f"{d}_{x}" for d in DIM4[2:] for x in ("pre", "post", "how", "review")] + ["coded_note"]
POST_R = lambda r: [x for d in DIM4[:2] for x in post3(r, d)] + [g(r, "dependency")] + [x for d in DIM4[2:] for x in post3(r, d)] + [NOTE[r["id"]]]
dataset("dataset_post.csv", POST_H, POST_R)
dataset("dataset_post_2026.csv", POST_H, POST_R, keep=lambda r: r["year"] == 2026)   # the 2026-only cut (every 2026 record, misplaced ones included)

# ---------------------------------------------------------------- markdown
pct = lambda a, b: f"{100*a/b:.1f}" if b else "—"
ch = lambda rows: collections.Counter(source_class(r) for r in rows)
val = lambda dim: (lambda r: M[r["id"]][dim])
NO_ATT = "no attacker: operator harm or model failure (misplaced record)"; NONE_W = RECLASS["ai_role"][0][1]
# Residue values: the dimension does not fit the record. Kept as rows and counted in each table's title.
res_kind = lambda v: "'other'" if v == "other" or v.startswith("other (") else "'no attacker'" if v.startswith("no attacker") else "'none'" if v.startswith("none:") else None
res_phrase = lambda vals: (lambda k: " or ".join([", ".join(k[:-1]), k[-1]]) if len(k) > 1 else k[0])([x for x in ("'other'", "'no attacker'", "'none'") if x in {res_kind(v) for v in vals}])
AG = CODED["meta"]["agreement"]
chan_n = lambda P: ", ".join(f"{x} {ch(P)[x]:,}" for x in CHANNELS)
NW_CH = collections.Counter(source_class(r) for r in WI if M[r["id"]]["ai_role"] == NONE_W)
NW_INTR = sum(M[r["id"]]["ai_role"] == NONE_W and M[r["id"]]["objective"] == "intrusion / cyber operation" for r in WI)
DROP5 = {"ON-AI": sum(M[r["id"]]["entry_point"] == NO_ATT for r in ON),
         "WITH-AI": sum(M[r["id"]]["ai_role"] in (NO_ATT, NONE_W) for r in WI)}   # records step 5 leaves out (no adversary; a CVE with no AI medium)
L = ["# Step 4 — Entry point, target, AI medium and objective (reviewed data)", "",
     "Each ON-AI record has an entry point (Table 4.1) and a target (4.2); each WITH-AI record has an AI medium (4.4) and an attacker objective (4.5). "
     "These are the cleaned labels that every later step uses.", "",
     "**How the labels were made.** Keyword rules on the title, description and affected field set a first value (the lists ENTRY, TARGET, AIROLE and OBJECTIVE in `s04_methodology.py`); "
     "where none matched, the corpus attack-vector label set it if that label maps to a single value, then a label-group rule (a group of attack-vector labels, or for the target a tracker-stub description), "
     f"and the records still without a value were labelled from the text by two independent coders with an adjudicator (`coded/relabels.json`; the coders agreed on "
     + ", ".join(f"{AG[d]['coders_agreed']} of {AG[d]['records']} {PLURAL[d]}" for d in DIM4) + ").", "",
     *([f"**How the labels were reviewed.** Every one of the {sum(len(POP[d]) for d in DIM4):,} labels was then read by two independent reviewers who saw the record's title, description, affected field "
        "and corpus labels but not how the label had been set. Each judged the label correct or proposed another value from the same list. When the two disagreed, an adjudicator decided; "
        "a final pass made each record's two labels agree on whether any adversary is described. Table 4.0 gives the agreement; `coded/review.json` holds every decision and "
        "`coded/review_verdicts.json` every reviewer's verdict and note. Step 6 compares these labels with the first values (keyword rule or corpus attack-vector label)."] if REVIEW else []), "",
     f"**Values that mark a misplaced or unplaceable record.** They stay visible in Tables 4.1, 4.2, 4.4 and 4.5. Only the first two mark a misplaced record, and step 5 leaves those out "
     f"({DROP5['ON-AI']} ON-AI and {DROP5['WITH-AI']} WITH-AI records):", "",
     f"- *{NO_ATT}*: no adversary is described (a product failure, policy, court, lawsuit, deployment or benchmark story).",
     f"- *{NONE_W}*: a conventional-exploit or malicious-package record placed in WITH-AI ({', '.join(f'{n} {x}' for x, n in NW_CH.most_common())}); no AI medium is involved. In Table 4.5 these records carry the objective 'intrusion / cyber operation' "
     f"({NW_INTR} of that row's {sum(M[r['id']]['objective'] == 'intrusion / cyber operation' for r in WI)}).",
     f"- *{T_STUB}*: a pointer to an external tracker that names no attacked system.",
     "- *other*: an adversary is described but no value fits, for instance an AI-assisted scam whose victim is not an AI system.", "",
     "**Files.** `out/dataset_post.csv` holds every ON-AI and WITH-AI record with its reviewed labels (`<dim>_post`) and the coder's or reviewer's note (`coded_note`); "
     "its audit columns (`<dim>_pre`, `<dim>_how`, `<dim>_review`) are explained in the README. `out/dataset_post_2026.csv` holds its 2026 rows; `out/dataset_pre.csv` holds the first values step 6 compares with. "
     "The dimensions are `entry_point`, `target`, `ai_role` (= AI medium) and `objective`, empty when not asked of the record's population; `dependency` holds Table 4.3's value. "
     "All files are written by `s04_methodology.py` (`make s04`), never by hand.", "",
     f"Records entered the populations by step 2's rules (Table 2.4). By channel ON-AI has {chan_n(ON)} records and WITH-AI {chan_n(WI)} "
     f"(channel columns are % of that channel, so each {100/ch(WI)['research/other']:.1f} in WITH-AI's research/other column is one record).", "", READ]
FULL = False
if REVIEW:
    ag = REVIEW["agreement"]; tl = sum(x["labels"] for x in ag.values())
    agree = lambda x: x.get("both_accepted", 0) + x.get("both_rejected_same", 0); adjd = lambda x: x.get("split_corrected", 0) + x.get("split_kept", 0)
    FULL = tl >= sum(len(POP[d]) for d in DIM4)
    L += ["", f"**Table 4.0. Review: the two reviewers reached the same label on {pct(sum(agree(x) for x in ag.values()), tl)}% of {tl:,} labels without the adjudicator** (n = labels)", "",
          "*Same label* = both reviewers ended on the same value; *adjudicated* = they differed and the adjudicator chose; *set by the final pass* = labels the last adjudicator decided "
          "so that the record's two labels agree on whether an adversary is described. The adjudicated share is the only measure here of how far reviewers could disagree. "
          + (lambda m, n1: f"Reviewers: two Claude Fable 5.1 reviewers read {n1 + m['pass2_reviewer_pairs'].get('claude-fable-5-1 + claude-fable-5-1', 0):,} labels "
             f"({n1} of them first, as a stratified sample); one Fable 5.1 and one Claude Opus 5.5 read {m['pass2_reviewer_pairs'].get('claude-fable-5-1 + claude-opus-5-5', 0):,}, "
             f"and two Opus 5.5 read {m['pass2_reviewer_pairs'].get('claude-opus-5-5 + claude-opus-5-5', 0):,} after a usage limit. The adjudicator was Fable 5.1 for the first {n1} labels "
             "and Opus 5.5 for the rest and the final pass.")(REVIEW["meta"]["models"], REVIEW["meta"]["labels_reviewed"] - sum(REVIEW["meta"]["models"]["pass2_reviewer_pairs"].values())), "",
          "| dimension | labels | reviewers reached the same label | adjudicated | set by the final pass |", "|---|---|---|---|---|"]
    for d in DIM4:
        x = ag[d]
        L.append(f"| {'ON-AI' if POP[d] is ON else 'WITH-AI'} {NAME[d]} | {x['labels']:,} | {agree(x):,} ({pct(agree(x), x['labels'])}%) | {adjd(x):,} ({pct(adjd(x), x['labels'])}%) | {x.get('consistency_changed', 0):,} |")
    L.append(f"| **all four** | {tl:,} | {sum(agree(x) for x in ag.values()):,} ({pct(sum(agree(x) for x in ag.values()), tl)}%) | {sum(adjd(x) for x in ag.values()):,} ({pct(sum(adjd(x) for x in ag.values()), tl)}%) | {sum(x.get('consistency_changed', 0) for x in ag.values()):,} |")
def post_table(d, question):
    P = POP[d]; c = collections.Counter(M[r["id"]][d] for r in P); top, tn = c.most_common(1)[0]; oth = sum(bool(res_kind(v)) for v in c.elements())
    desc = "Reviewed values, largest first; the 'no attacker', 'none' and 'other' values are defined above."
    return table(f"{'ON-AI' if P is ON else 'WITH-AI'}: {question} {top} {pct(tn, len(P))}%; {pct(oth, len(P))}% {res_phrase(c)}",
                 P, val(d), ci=True, channels=True, num=NUM[d], top=len(c), rest=False, desc=desc)
L += post_table("entry_point", "how did the adversary first reach the AI system?")
L += post_table("target", "which part of the AI stack was attacked?")
CVE, MV = "CVE/CWE present (software vulnerability)", "model-level attack vector, no CVE/CWE"; dc = collections.Counter(dep(r) for r in ON)
both_dep = sum(bool(r.get("cve_ids") or r.get("cwe_ids")) and r["attack_vector"] in MODEL_VEC for r in ON)
L += table(f"ON-AI: does the record carry a CVE/CWE ({100*dc[CVE]/len(ON):.0f}%), a model-level attack vector ({100*dc[MV]/len(ON):.0f}%) or neither ({100*dc['unstated']/len(ON):.0f}%)?", ON, dep, ci=True, num="4.3",
           desc=f"Read off corpus fields; not part of the review: a CVE or CWE id, else one of the {len(MODEL_VEC)} model-level attack-vector labels ({', '.join(MODEL_VEC)}), else unstated. "
                f"No channel columns because every CVE/CWE record is cve/ghsa; {both_dep} records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor.")
L += post_table("ai_role", "what did the AI generate: image, voice, text, video or code?")
L += post_table("objective", "what was the attacker after?")
write("s04_methodology.md", L)
