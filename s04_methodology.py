#!/usr/bin/env python3
"""s04_methodology.py — Step 4. Entry point, target, AI medium and objective for ON-AI and WITH-AI, after reclassifying the unstated records.
Per record and dimension the value is assigned in a fixed order, first hit wins: text rule (ENTRY/TARGET/AIROLE/OBJECTIVE, keyword patterns
over title+description+affected) → corpus-label fallback (FALLBACK, attack-vector label → value where unambiguous) → label-group rule
(RECLASS, a group of attack-vector labels or a tracker-stub description → value) → coded label (coded/relabels.json: two independent coders,
a third adjudicating) → 'other' (a safety net, asserted never to fire). The 'pre' value is the one after the first two steps, 'unstated' kept.
Outputs: out/methodology.json (id → post values, _pre, _how, _match (words a text rule matched), dependency; s05 reads 'objective'), out/dataset_pre.csv, out/dataset_post.csv,
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
STRATUM_N = collections.Counter((d, M[r["id"]][d], M[r["id"]][d + "_how"]) for d in DIM4 for r in POP[d])   # rule-assigned population per (dim, value, how), before any correction
STRATUM_N_HOW = collections.Counter((d, M[r["id"]][d + "_how"]) for d in DIM4 for r in POP[d])
ASG = {}   # (id, dim) -> the value before review, for labels the review corrected
if REVIEW:   # corrections from the two-reviewer sample audit override the rule value; the pre value and the audit trail stay
    for c in REVIEW["corrections"]:
        m = M[c["id"]]; assert m[c["dim"]] == c["from"], c
        m[c["dim"] + "_pre_how"] = m[c["dim"] + "_how"]   # the rule source stays with the pre value in dataset_pre.csv
        ASG[(c["id"], c["dim"])] = c["from"]
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
dataset("dataset_post_2026.csv", POST_H, POST_R, keep=lambda r: r["year"] == 2026)   # the 2026-only cut read by step 5's Table 5.4

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
     "Each ON-AI record gets an entry point (Table 4.1) and a target (4.2), each WITH-AI record an AI medium (4.4) and an attacker objective (4.5). "
     "Four assignment steps run in order, first hit wins" + (", and every label is then reviewed:" if REVIEW else ":"), "",
     "1. **Text rule.** Ordered keyword patterns over title + description + affected (the lists ENTRY, TARGET, AIROLE and OBJECTIVE in `s04_methodology.py`).",
     f"2. **Corpus label.** The attack-vector label, where it maps to exactly one value of the dimension: {'; '.join(fb_clause(d) for d in DIM4 if FALLBACK[d])}.",
     f"3. **Label-group rule.** A group of attack-vector labels fixes the value: {'; '.join(rc_clause(d) for d in DIM4 if RECLASS[d])}. "
     "For the target, which no label names, this step is instead a tracker-stub test (a description starting " + " or ".join(f"'{s}'" for s in STUB) + f" → {T_STUB}), placed after the keyword rules so that a system named in the text wins.",
     f"4. **Coded from text.** Records still unstated were labelled by {CODED['meta']['coders']}; coders agreed on "
     + ", ".join(f"{AG[d]['coders_agreed']} of {AG[d]['records']} {PLURAL[d]}" for d in DIM4) + f" (`coded/relabels.json`; `meta.codebook` is the value menu). "
     f"The script checks that the file covers exactly the records steps 1–3 leave unstated; a final 'other' safety net fired {sum(left.values())} times (the script stops if it fires).",
     *([f"5. **Review.** Two independent reviewers read every label from the record text without seeing which step set it; an adjudicator settled splits, and a last pass made each record's two labels agree on whether an adversary is described. "
        f"A correction replaces the value (how = 'corrected by review'); Tables 4.0b–4.0d report it (`coded/review.json`, every verdict in `coded/review_verdicts.json`)."] if REVIEW else []), "",
     f"Four values mark records the dimension does not fit. They stay visible as rows, and none is moved or dropped (step 5 reads `objective` from `out/methodology.json`):", "",
     f"- *{NO_ATT}*: no adversary is described (a product failure, policy, court, lawsuit, deployment or benchmark story), so the record belongs in neither population.",
     f"- *{NONE_W}*: a software-vulnerability record (CVE/GHSA) that step 2 placed in WITH-AI; no AI medium is involved.",
     f"- *{T_STUB}*: a pointer to an external tracker that names no attacked system.",
     "- *other*: an adversary is described but no value fits, for instance an AI-assisted scam in ON-AI whose victim is not an AI system.", "",
     "Files, all written by `s04_methodology.py` (`make s04`), never by hand. `out/dataset_pre.csv` holds every ON-AI and WITH-AI record with the values after steps 1–2 ('unstated' kept), "
     "as `<dim>` and `<dim>_source` (text rule / corpus label / unstated). `out/dataset_post.csv` holds `<dim>_pre`, `<dim>_post`, `<dim>_how` (the step that fixed the final value) "
     "and `<dim>_review` (confirmed / corrected / kept with dissent), plus `coded_note` ('dimension: reason' from the coders or reviewers); `out/dataset_post_2026.csv` is its 2026 rows. "
     "The dimensions are `entry_point`, `target`, `ai_role` (= AI medium) and `objective`, empty when not asked of the record's population; `dependency` holds Table 4.3's value for every record.", "",
     f"Records entered the populations by step 2's rules (Table 2.4). By channel ON-AI has {chan_n(ON)} records and WITH-AI {chan_n(WI)} "
     f"(channel columns are % of that channel, so each {100/ch(WI)['research/other']:.1f} in WITH-AI's research/other column is one record).", "", READ, "",
     f"**Table 4.0. How each value was assigned** (ON-AI n = {len(ON):,}; WITH-AI n = {len(WI):,})", "",
     "Counts of records per dimension by the step that fixed the final value (the step columns sum to the records); the last column counts records holding one of the four residue values defined above, whichever step set them. In the notes of Tables 4.1–4.5, 'rule' = label-group rule, 'coded' = coded from text, 'review' = corrected by review, and * marks a value that did not exist before this step.", "",
     "| dimension (table) | records | text rule | corpus label | label-group rule | coded from text (coders agreed / adjudicated) |" + (" corrected by review |" if REVIEW else "") + " value 'other', 'no attacker' or 'none' |", "|---|---|---|---|---|---|" + ("---|" if REVIEW else "") + "---|"]
T0 = {}
for d in DIM4:
    P = POP[d]; hc = collections.Counter(M[r["id"]][d + "_how"] for r in P); cs = [CODED["labels"][d][r["id"]] for r in P if M[r["id"]][d + "_how"] == HOW[3]]
    adj = sum(c["adjudicated"] for c in cs); oth = sum(bool(res_kind(M[r["id"]][d])) for r in P); cell = lambda a: f"{a:,} ({pct(a, len(P))}%)"
    T0[d] = (len(P), hc[HOW[0]], hc[HOW[1]], hc[HOW[2]], len(cs), len(cs) - adj, adj, oth)
    L.append(f"| {'ON-AI' if P is ON else 'WITH-AI'} {NAME[d]} ({NUM[d]}) | {len(P):,} | {cell(hc[HOW[0]])} | {cell(hc[HOW[1]])} | {cell(hc[HOW[2]])} | {cell(len(cs))} ({len(cs) - adj} / {adj}) |" + (f" {cell(hc[HOW[5]])} |" if REVIEW else "") + f" {cell(oth)} |")
if REVIEW:
    st = REVIEW["strata"]; tot = {k: sum(x[k] for x in st) for k in ("reviewed", "correct", "corrected", "disputed")}; n_labels = sum(len(POP[d]) for d in DIM4)
    FULL = all(STRATUM_N[(x["dim"], x["value"], x["how"])] <= x["reviewed"] for x in st) and tot["reviewed"] >= n_labels
    by_step = collections.defaultdict(lambda: {"reviewed": 0, "kept": 0, "corrected": 0, "to": collections.Counter()})
    for x in st:
        b_ = by_step[(x["dim"], x["how"])]; b_["reviewed"] += x["reviewed"]; b_["kept"] += x["correct"] + x["disputed"]; b_["corrected"] += x["corrected"]; b_["to"].update(x["corrected_to"])
    L += ["", f"**Table 4.0b. Review by assignment step: {pct(tot['correct'] + tot['disputed'], tot['reviewed'])}% of {tot['reviewed']:,} reviewed labels were kept, {tot['corrected']:,} corrected** "
              f"(n = {tot['reviewed']:,} of {n_labels:,} labels)", "",
          "Per dimension and the step that had assigned the label: how many labels that step set, how many the review read, how many it kept (both reviewers accepted, or the adjudicator kept it over one dissent) "
          "and how many it corrected, with the two most common replacements. "
          + ("Every label was read, so 'kept' is the precision of that step." if FULL else f"A stratified sample of at most {REVIEW['meta']['per_value']} labels per value was read, so 'kept' estimates the precision of that step.")
          + " Per-value detail: Table 4.0d.", "",
          "| dimension | assigned by | labels | reviewed | kept | corrected | main replacements |", "|---|---|---|---|---|---|---|"]
    for d in DIM4:
        for h in HOW[:4]:
            b_ = by_step.get((d, h))
            if not b_: continue
            top = ", ".join(f"{v} {n}" for v, n in b_["to"].most_common(2)) or "—"
            L.append(f"| {NAME[d]} | {h} | {STRATUM_N_HOW[(d, h)]:,} | {b_['reviewed']:,} | {b_['kept']:,} ({pct(b_['kept'], b_['reviewed'])}%) | {b_['corrected']:,} | {top} |")
    for h in HOW[:4]:   # pooled over the four dimensions, per step
        bs = [by_step[(d, h)] for d in DIM4 if (d, h) in by_step]; rv = sum(b_["reviewed"] for b_ in bs); kp = sum(b_["kept"] for b_ in bs)
        L.append(f"| **all four** | {h} | {sum(STRATUM_N_HOW[(d, h)] for d in DIM4):,} | {rv:,} | {kp:,} ({pct(kp, rv)}%) | {sum(b_['corrected'] for b_ in bs):,} | |")
    if FULL:   # every label read: the remaining error is reviewer error, bounded by how often the two reviewers disagreed
        ag = REVIEW["agreement"]; tl = sum(a["labels"] for a in ag.values()); sp = sum(a.get("split_corrected", 0) + a.get("split_kept", 0) for a in ag.values()); cons = sum(a.get("consistency_changed", 0) for a in ag.values())
        L += ["", f"**Table 4.0c. Reviewer agreement: the two reviewers settled {pct(tl - sp - cons, tl)}% of labels between them; the adjudicator decided {sp:,}; {cons} more were changed to make a record's two labels agree** (n = {tl:,} labels)", "",
              f"{REVIEW['meta']['design']} Columns: labels both reviewers accepted, labels both rejected with the same replacement, splits (one accepted, or two different replacements) by how the adjudicator settled them, "
              "and labels changed afterwards because the record's other dimension said 'no attacker' and this one did not (or the reverse). "
              "The remaining error in Tables 4.1–4.5 is reviewer error, for which the split rate is the only measure here; every reviewer verdict and note is in `coded/review_verdicts.json`.", "",
              "| dimension | labels | both accepted | both rejected, same replacement | split, adjudicator corrected | split, adjudicator kept | changed for consistency |", "|---|---|---|---|---|---|---|"]
        for d in DIM4:
            a = ag[d]; cell = lambda k: f"{a.get(k, 0):,} ({pct(a.get(k, 0), a['labels'])}%)"
            L.append(f"| {NAME[d]} | {a['labels']:,} | {cell('both_accepted')} | {cell('both_rejected_same')} | {cell('split_corrected')} | {cell('split_kept')} | {cell('consistency_changed')} |")
    else:
      # population-weighted view: each stratum's observed error rate (corrected / reviewed) applied to the records of that stratum the sample did not reach
      L += ["", f"**Table 4.0c. What the review implies for the labels it did not read** (rule-assigned labels per dimension)", "",
          f"{REVIEW['meta']['design']} The sample took at most 20 records per value, so small values were read in full and large ones were not. 'estimated wrong before review' applies each value's observed error rate to all of its records; "
          "'still wrong after correction' is the same estimate for the records the sample did not reach, i.e. the error that remains in Tables 4.1–4.5 and `out/dataset_post.csv`. Values read in full contribute no remaining error.", "",
          "| dimension | rule-assigned labels | read in full (values) | reviewed | corrected | estimated wrong before review | still wrong after correction |", "|---|---|---|---|---|---|---|"]
      for d in DIM4:
        rows = [x for x in st if x["dim"] == d]; n_all = sum(n for (dd, v, h), n in STRATUM_N.items() if dd == d and h in HOW[:3])
        full = sum(STRATUM_N[(d, x["value"], x["how"])] <= x["reviewed"] for x in rows)
        est = sum(STRATUM_N[(d, x["value"], x["how"])] * x["corrected"] / x["reviewed"] for x in rows)
        rem = sum(max(STRATUM_N[(d, x["value"], x["how"])] - x["reviewed"], 0) * x["corrected"] / x["reviewed"] for x in rows)
        L.append(f"| {NAME[d]} | {n_all:,} | {full} of {len(rows)} | {sum(x['reviewed'] for x in rows)} | {sum(x['corrected'] for x in rows)} | {est:,.0f} ({pct(est, n_all)}%) | {rem:,.0f} ({pct(rem, n_all)}%) |")
    # each value through the chain: rule value (pre), value before review, kept by review, moved out (where to), moved in, final
    L += ["", "**Table 4.0d. Each value from rule to final** (per dimension, largest final value first)", "",
          "*Pre* = the value a text rule or corpus label set, as in `out/dataset_pre.csv` ('unstated' otherwise); *before review* = the value after the label-group rule and the coders; "
          "*kept* = labels the review left in place; *moved out* = labels the review took away, with where most went; *moved in* = labels the review gave this value; "
          "*final* = kept + moved in, the value in Tables 4.1–4.5 and `out/dataset_post.csv`.", "",
          "| dimension | value | pre | before review | kept | moved out (main destinations) | moved in | final n (%) |", "|---|---|---|---|---|---|---|---|"]
    for d in DIM4:
        P = POP[d]; before = lambda r: ASG.get((r["id"], d), M[r["id"]][d])
        c0 = collections.Counter(M[r["id"]][d + "_pre"] for r in P); cb = collections.Counter(before(r) for r in P); c1 = collections.Counter(M[r["id"]][d] for r in P)
        kept = collections.Counter(M[r["id"]][d] for r in P if before(r) == M[r["id"]][d]); out_to = collections.defaultdict(collections.Counter)
        for r in P:
            if before(r) != M[r["id"]][d]: out_to[before(r)][M[r["id"]][d]] += 1
        for v in sorted(set(c0) | set(cb) | set(c1), key=lambda v: (-c1[v], v)):
            mo = sum(out_to[v].values()); dest = ", ".join(f"{w} {n}" for w, n in out_to[v].most_common(2))
            L.append(f"| {NAME[d]} | {v} | {c0[v]:,} | {cb[v]:,} | {kept[v]:,} | {mo:,}{' (' + dest + ')' if mo else ''} | {c1[v] - kept[v]:,} | {c1[v]:,} ({pct(c1[v], len(P))}%) |")
SHORT = {HOW[2]: "rule", HOW[3]: "coded", HOW[5]: "review"}
def post_table(d, question):
    P = POP[d]; c = collections.Counter(M[r["id"]][d] for r in P); top, tn = c.most_common(1)[0]; oth = sum(bool(res_kind(v)) for v in c.elements())
    un = [r for r in P if M[r["id"]][d + "_pre"] == "unstated"]; cu = collections.Counter(M[r["id"]][d] for r in un)
    hows = {v: collections.Counter(M[r["id"]][d + "_how"] for r in un if M[r["id"]][d] == v) for v in cu}
    how_s = lambda v: ", ".join(f"{SHORT[h]} {n}" for h, n in hows[v].most_common()) if len(hows[v]) > 1 else SHORT[hows[v].most_common(1)[0][0]]
    known = {n for n, _ in DIMS[d]} | set(FALLBACK[d].values())
    desc = (f"Before reclassification {len(un):,} records ({pct(len(un), len(P))}%) were unstated; they now hold, largest first: "
            + "; ".join(f"{v}{'' if v in known else '*'} {n} ({how_s(v)})" for v, n in cu.most_common())
            + ".")
    if REVIEW:   # values whose rule-assigned labels the audit found mostly wrong: the unreviewed remainder of such a value carries that error
        prec = collections.defaultdict(lambda: [0, 0])
        for x in REVIEW["strata"]:
            if x["dim"] == d: prec[x["value"]][0] += x["correct"] + x["disputed"]; prec[x["value"]][1] += x["reviewed"]
        low = sorted(((v, a, b) for v, (a, b) in prec.items() if a < b / 2), key=lambda t: t[1] / t[2])
        if low and FULL: desc += (" Review (Table 4.0d): the review kept fewer than half of the labels first given "
                                  + ", ".join(f"{v} ({a} of {b})" for v, a, b in low) + "; every label was read and the wrong ones corrected.")
        elif low: desc += (" Audit (Table 4.0b): fewer than half of the sampled rule-assigned labels were correct for "
                           + ", ".join(f"{v} ({a} of {b})" for v, a, b in low) + "; the unreviewed records under these values carry that error rate.")
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
