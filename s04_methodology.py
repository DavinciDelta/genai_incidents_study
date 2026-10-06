#!/usr/bin/env python3
"""s04_methodology.py — Step 4. Entry point, target, AI medium and objective for ON-AI and WITH-AI, in two tiers.
Tier 1: keyword rules over title+description+affected, tried in order, first match wins. Tier 2: when no rule matches, the corpus
attack-vector label is mapped to a value where the mapping is unambiguous (FALLBACK). 'unstated' = neither. Every value records
its source. Output: out/methodology.json (id → entry_point, target, ai_role, objective, <dim>_source, dependency; read by s05)
and out/s04_methodology.md
"""
import collections, json, re
from common import load_full, load_rv, join_rv, source_class, text, table, write, READ, OUT, CHANNELS
S = json.load(open(OUT / "split.json")); C = load_full()
RX = lambda p: re.compile(p, re.I)
def first(rules, t, default="unstated"):
    return next((name for name, rx in rules if rx.search(t)), default)
# Word-boundary fragments that replaced bare substrings; DEFECTS below holds the old fragment so Table 4.7 can count both.
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
# Second tier: corpus attack-vector label → value, only where the mapping is unambiguous. Two values exist only here, because the
# label says less than the text rules ask: a prompt-injection label does not say whether the prompt was the user's own or carried
# in content, and a deepfake label does not say image, voice or video. The target has no fallback: the label names no component.
PI_LABEL, DK_LABEL = "prompt injection, carrier not stated (corpus label)", "deepfake, medium not stated (corpus label)"
FALLBACK = {"entry_point": {"malware": ENTRY[2][0], "supply-chain": ENTRY[2][0], "backdoor": ENTRY[2][0], "adversarial-input": ENTRY[5][0], "evasion": ENTRY[5][0],
                            "indirect-prompt-injection": ENTRY[0][0], "prompt-injection": PI_LABEL, "jailbreak": PI_LABEL},
            "target": {}, "ai_role": {"csam-generation": AIROLE[2][0], "deepfake": DK_LABEL}, "objective": {"csam-generation": OBJECTIVE[2][0]}}
EXTRA = {"entry_point": [PI_LABEL], "target": [], "ai_role": [DK_LABEL], "objective": []}  # the label-only values, for the appendix rows
def classify(r, dim):
    v = first(DIMS[dim], text(r), None)
    if v: return v, "text"
    v = FALLBACK[dim].get(r["attack_vector"]); return (v, "label") if v else ("unstated", "none")
# (dimension, rule name, what the old substring also matched, old fragment, new fragment, the fix in words). Table 4.7 recomputes both.
DEFECTS = [("entry_point", ENTRY[0][0], "'document' in 'documentation'", r"document", r"\bdocuments?\b", "whole word, singular or plural"),
           ("target", TARGET[0][0], "'cline' in 'declined'", r"cline", r"\bcline\b", "whole word"),
           ("target", TARGET[0][0], "'dify' in 'modify'", r"dify", r"\bdify\b", "whole word"),
           ("target", TARGET[1][0], "'llama' in 'Ollama'", r"llama", r"(?<!o)llama", "not preceded by 'o'"),
           ("target", TARGET[5][0], "missed 'facial-recognition'", r"facial recognition", r"facial[- ]recognition", "space or hyphen"),
           ("ai_role", AIROLE[4][0], "'script', 'payload' in 'JavaScript', 'HTML payload'", r"script|payload", CODE_FRAG, "only in an 'AI-generated script / payload / code' phrase"),
           ("objective", OBJECTIVE[0][0], "'invest' in 'investigation'", r"invest", r"\binvest(ments?|ors?|ing|ed|s)?\b", "whole word, inflections allowed"),
           ("objective", OBJECTIVE[1][0], "'party' in 'third party', 'httparty'", r"party", r"(?<!third[- ])(?<!http)\bparty\b", "whole word, not preceded by 'third' or 'http'"),
           ("objective", OBJECTIVE[4][0], "'apt' in 'captured'", r"apt", r"\bapt\d*\b", "whole word, digits allowed")]
DIM_NAME = {"entry_point": "4.1", "target": "4.2", "ai_role": "4.4", "objective": "4.5"}
MODEL_VEC = ("prompt-injection", "indirect-prompt-injection", "jailbreak", "adversarial-input", "evasion", "model-extraction", "membership-inference", "model-inversion")
def dep(r):
    if r.get("cve_ids") or r.get("cwe_ids"): return "CVE/CWE present (software vulnerability)"
    if r["attack_vector"] in MODEL_VEC: return "model-level attack vector, no CVE/CWE"
    return "unstated"
ON = [C[i] for i, s in S.items() if s["population"] == "ON-AI"]; WI = [C[i] for i, s in S.items() if s["population"] == "WITH-AI"]
M = {}
for r in ON + WI:
    m = {"dependency": dep(r)}
    for d in DIMS: m[d], m[d + "_source"] = classify(r, d)
    M[r["id"]] = m
json.dump(M, open(OUT / "methodology.json", "w"), indent=0); print(f"wrote out/methodology.json ({len(M):,} records)")

# ---------------------------------------------------------------- helpers
POP = {"entry_point": ON, "target": ON, "ai_role": WI, "objective": WI}
pct = lambda a, b: f"{100*a/b:.1f}" if b else "—"
ch = lambda rows: collections.Counter(source_class(r) for r in rows)
med = lambda xs: (sorted(xs)[len(xs) // 2] if xs else 0)
cut = lambda t, k: t if len(t) <= k else t[:k].rsplit(" ", 1)[0] + "…"
val = lambda dim: (lambda r: M[r["id"]][dim])
tv = lambda r, dim: M[r["id"]][dim] if M[r["id"]][dim + "_source"] == "text" else "unstated"  # text tier alone, for Table 4.7
SRC = {"text": "from the text", "label": "from the corpus label"}
by_label = lambda dim, v=None: [r for r in POP[dim] if M[r["id"]][dim + "_source"] == "label" and (v is None or M[r["id"]][dim] == v)]
def prov(dim):  # breakdown: source under every value with label-derived records, attack-vector group under unstated
    return {**{v: (lambda r, d=dim: SRC[M[r["id"]][d + "_source"]]) for v in {M[r["id"]][dim] for r in by_label(dim)}}, "unstated": vgroup}
def swap(rules, name, new, old):  # the same rule list with one fragment put back to its old form
    return [(n, RX(rx.pattern.replace(new, old)) if n == name else rx) for n, rx in rules]
multi = lambda dim: sum(sum(bool(rx.search(text(r))) for _, rx in DIMS[dim]) > 1 for r in POP[dim])  # records where first-match order decided
STUBS = [("OECD pointer stub ('Tracked by the OECD …')", lambda r: r["description"].startswith("Tracked by the OECD")),
         ("AIID title-repeat stub ('AI Incident Database (AIID) entry #N: …')", lambda r: r["description"].startswith("AI Incident Database (AIID) entry #")),
         ("AIAAIC facts-only stub ('AIAAIC-tracked incident. Technology: … Sector: …')", lambda r: r["description"].startswith("AIAAIC-tracked incident"))]
NARR = "narrative description"
stub_kind = lambda r: next((k for k, f in STUBS if f(r)), NARR)
# The OECD stub repeats the record's attack_vector label in a 'Classified attack vector: <value>.' sentence; it is removed before asking
# whether the source itself says 'deepfake', so the two tiers stay distinct.
LABEL_LINE = RX(r"Classified attack vector: ([a-z-]+)\.?")
says_deepfake = lambda r: "deepfake" in f"{r['title']} {LABEL_LINE.sub('', r['description'])} {r.get('affected') or ''}".lower()
VEC_GROUPS = [("conventional software exploit", {"rce", "ssrf", "sql-injection", "command-injection", "path-traversal", "deserialization", "xss", "auth-bypass", "info-disclosure", "dos", "csrf", "data-exfiltration"}),
              ("malicious package / backdoor / supply chain", {"malware", "supply-chain", "backdoor"}),
              ("prompt injection / jailbreak", {"prompt-injection", "indirect-prompt-injection", "jailbreak"}),
              ("adversarial input / evasion", {"adversarial-input", "evasion"}),
              ("inference attack", {"membership-inference", "model-extraction", "model-inversion"}),
              ("agent / sandbox / tool abuse", {"sandbox-escape", "tool-abuse", "agent-hijack", "memory-poisoning"}),
              ("training / model poisoning", {"model-poisoning"}),
              ("deepfake (names a medium, not an objective)", {"deepfake"})]
OTHER_G = "'other' / harm-type vector"
vgroup = lambda r: next((g for g, vs in VEC_GROUPS if r["attack_vector"] in vs), OTHER_G)
other_labels = sorted({r["attack_vector"] for r in ON + WI if vgroup(r) == OTHER_G})
chan_note = lambda P: "(" + ", ".join(f"{x} {ch(P)[x]:,}" for x in CHANNELS) + " records; channel columns are % of that channel)"
un = lambda dim: [r for r in POP[dim] if M[r["id"]][dim] == "unstated"]
nlab = lambda dim: len(by_label(dim))
rule_n = lambda rule, P: sum(S[r["id"]]["rule"] == rule for r in P)
DIM_LABEL = {"entry_point": "entry point (4.1)", "ai_role": "AI medium (4.4)", "objective": "objective (4.5)"}

# ---------------------------------------------------------------- ON-AI
e_un = un("entry_point")
conv = [r for r in e_un if vgroup(r) == VEC_GROUPS[0][0]]; pi = by_label("entry_point", PI_LABEL)
pi_stub = [r for r in pi if stub_kind(r) != NARR]; pi_word = [r for r in pi if stub_kind(r) == NARR and "prompt" in text(r).lower()]
ag = [r for r in ON if M[r["id"]]["target"] == TARGET[0][0]]; bare = [r for r in ag if not RX(TARGET[0][1].pattern.replace(r"\bagent|", "")).search(text(r))]
noise = sum(bool(RX(r"user[- ]agent|threat agent|agentless").search(text(r))) for r in bare); ai_ag = sum(bool(RX(r"(ai|llm|coding|autonomous) agents?|agentic").search(text(r))) for r in bare)
both_dep = sum(bool(r.get("cve_ids") or r.get("cwe_ids")) and r["attack_vector"] in MODEL_VEC for r in ON); dc = collections.Counter(dep(r) for r in ON)
assert {source_class(r) for r in ON if r.get("cve_ids") or r.get("cwe_ids")} == {"cve/ghsa"} and not any((r.get("cve_ids") or r.get("cwe_ids")) and source_class(r) != "cve/ghsa" for r in ON)
assert all(r["attack_vector"] not in FALLBACK[d] for d in DIMS for r in un(d)), "an unstated record carries a mapped label"
assert set(MODEL_VEC) == set().union(*(vs for _, vs in VEC_GROUPS[2:5])), "MODEL_VEC is not the three model-level groups"
L = ["# Step 4 — Entry point, target, AI medium and objective: text first, corpus label second, unstated otherwise", "",
     "Each ON-AI record gets an entry point (Table 4.1) and a target component (4.2), each WITH-AI record an AI medium (4.4) and an attacker objective (4.5), read from its title + description + affected text. "
     "Each dimension is an ordered list of values, each with a keyword pattern (the lists in the script); the first value whose pattern matches is assigned, so a record naming two entry points gets the earlier one "
     f"(the order decided {multi('entry_point')} entry points, {multi('target')} targets, {multi('ai_role')} media and {multi('objective')} objectives).", "",
     f"When no pattern matches, the corpus attack-vector label is read and assigned where it maps to exactly one value (`FALLBACK`, Table 4.0). The target has no fallback because the label names no component, and the {sum(map(len, EXTRA.values()))} '(corpus label)' values exist "
     "only in this tier because the label says less than the text rules ask (whether the prompt was the user's own or carried in content; whether the deepfake was image, voice or video). "
     "`unstated` = neither a pattern nor a mapped label, so every unstated record carries a label that maps to no value; the ↳ rows under unstated group that label: "
     + "; ".join(f"{g} = {', '.join(sorted(vs))}" for g, vs in VEC_GROUPS if len(vs) > 1) + f"; {OTHER_G} = {', '.join(other_labels)}.", "",
     f"**Table 4.0. The label fallback: {sum(map(len, FALLBACK.values()))} corpus labels map to a value when no pattern matches** ({sum(nlab(d) for d in DIMS):,} records)", "",
     "| dimension | corpus attack-vector label | value assigned |", "|---|---|---|"]
L += [f"| {DIM_LABEL[d]} | {', '.join(k for k, x in FALLBACK[d].items() if x == v)} | {v} |" for d in DIM_LABEL for v in dict.fromkeys(FALLBACK[d].values())]
L += ["", "Under every value with label-derived records the ↳ rows give the source ('from the text' / 'from the corpus label'); a value with no ↳ rows is text-only. "
      f"Records entered the populations by step 2's rules (Table 2.4): ON-AI by an ON attack-vector label (`on-vector`, {rule_n('on-vector', ON):,}), ON vocabulary in the text (`on-vocabulary`, {rule_n('on-vocabulary', ON):,}) "
      f"or an attacker word plus a conventional code vector (`conventional-exploit-of-ai-tooling`, {rule_n('conventional-exploit-of-ai-tooling', ON):,}); WITH-AI by a WITH attack-vector label (`with-vector`, {rule_n('with-vector', WI):,}) or WITH vocabulary (`with-vocabulary`, {rule_n('with-vocabulary', WI):,}). "
      "A tracker stub is a description that only points at the OECD, AIID or AIAAIC entry (forms in Table 4.2).", "",
      f"The coding work left is of three kinds: confirm the label-derived values against the source ({nlab('entry_point')} entry points, {nlab('ai_role')} media, {nlab('objective')} objectives; harm-db records first, Table 4.7b), "
      "extend the vocabulary where the text names a mechanism the lists miss, and go to the source tracker for the stubs; the ↳ rows under unstated size the last two per table. "
      "Generated by `s04_methodology.py` (`make s04`), never edited by hand. `out/methodology.json`: id → the four values, a `_source` per dimension (text / label / none) and dependency (Table 4.3); the unstated group is the corpus `attack_vector`.", "", READ,
      f"", f"## ON-AI {chan_note(ON)}"]
L += table(f"ON-AI: how did the adversary first reach the AI system? {100*len(e_un)/len(ON):.0f}% unstated, {len(conv)} of those a conventional exploit; {nlab('entry_point')} values from the label alone",
           ON, val("entry_point"), ci=True, channels=True, num="4.1", breakdown=prov("entry_point"),
           desc=f"{len(ENTRY)} text rules, then the label. Unstated: a conventional software exploit has no entry point ({len(conv)}; {ch(conv)['harm-db']} of them harm-db records whose label is a corpus keyword, so expect misfiles, Table 4.7b) "
                f"and the other groups name no way in. "
                f"Of the {len(pi)} label-only prompt-injection records, {len(pi_stub)} are tracker stubs, {len(pi_word)} narratives say 'prompt' in a phrase no rule lists and {len(pi) - len(pi_stub) - len(pi_word)} narratives say neither (jailbreak benchmarks, evaluations, advisories).")
t_un = un("target")
T_STUB, T_OUT, T_NONE = "tracker stub (OECD / AIID / AIAAIC form), no system named", f"product named in `affected`, outside the {len(TARGET)} lists (list gap)", "names no system (`affected` empty)"
tkind = lambda r: T_STUB if stub_kind(r) != NARR else (T_OUT if r.get("affected") else T_NONE)
norm = lambda a: re.sub(r"[^a-z0-9]", "", a.split(",")[0].split("/")[-1].lower())  # one spelling per product: last path segment, lower-case, alphanumerics
t_out = collections.defaultdict(collections.Counter)
for r in t_un:
    if tkind(r) == T_OUT: t_out[norm(r["affected"])][r["affected"]] += 1
n_out = sum(sum(c.values()) for c in t_out.values())
L += table(f"ON-AI: which part of the AI stack was attacked? Agents, copilots and MCP in {100*len(ag)/len(ON):.0f}%, and {100*ch(ag)['cve/ghsa']/len(ag):.0f}% of those {len(ag)} are CVE/GHSA records; {100*len(t_un)/len(ON):.0f}% unstated, {100*n_out/len(t_un):.0f}% of those a product the lists miss",
           ON, val("target"), ci=True, channels=True, num="4.2", breakdown=("unstated", tkind),
           desc=f"Text only, no label fallback: the same text is searched for product and component names in {len(TARGET)} lists, first matching list wins. "
                f"{len(bare)} of the {len(ag)} agent records match no list term except 'agent': {ai_ag} qualify it (AI, LLM, coding or autonomous agent, or agentic), {len(bare) - ai_ag} use the bare word, {noise} in the 'user agent' / 'threat agent' sense (pattern check). "
                f"The ↳ rows split the {len(t_un)} unstated records by corpus fields (stub forms: 'Tracked by the OECD …', 'AI Incident Database (AIID) entry #…', 'AIAAIC-tracked incident …'); "
                f"the {n_out} list-gap records name {len(t_out)} distinct products (spellings merged): "
                f"the target is stated, the lists are short ({sum(d == 'target' for d, *_ in DEFECTS)} substring defects in them: Table 4.7).")
CVE, MV = "CVE/CWE present (software vulnerability)", "model-level attack vector, no CVE/CWE"; d_un = [r for r in ON if dep(r) == "unstated"]
L += table(f"ON-AI: does the record carry a CVE/CWE ({100*dc[CVE]/len(ON):.0f}%), a model-level attack vector ({100*dc[MV]/len(ON):.0f}%) or neither ({100*dc['unstated']/len(ON):.0f}%)?", ON, dep, ci=True, num="4.3", breakdown=("unstated", vgroup),
           desc=f"Read off corpus fields: a CVE or CWE id, else one of the {len(MODEL_VEC)} model-level attack vectors (`MODEL_VEC`: the {', '.join(g for g, _ in VEC_GROUPS[2:5])} groups of the opener), else unstated; "
                "any other label with no CVE/CWE lands in unstated (hence the supply-chain and poisoning rows). No channel columns because every CVE/CWE record is cve/ghsa. "
                f"The ↳ rows split the {len(d_un)} unstated records by attack-vector group (harm-db {ch(d_un)['harm-db']}, research/other {ch(d_un)['research/other']}; {sum(stub_kind(r) != NARR for r in d_un)} tracker stubs). "
                f"{both_dep} records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor; `exploited_in_wild` is set on {sum(r.get('exploited_in_wild') is True for r in ON)} ON-AI records (Table 4.6), so nothing here says whether an attack succeeded.")

# ---------------------------------------------------------------- WITH-AI
m_un = un("ai_role"); dk = by_label("ai_role", DK_LABEL); dk_text = [r for r in dk if says_deepfake(r)]
dk_line = [r for r in dk if not says_deepfake(r) and "deepfake" in text(r).lower()]  # the word appears only in the OECD label sentence
assert all(LABEL_LINE.search(r["description"]).group(1) == r["attack_vector"] for r in dk_line)
wi_note = f"research/other has {ch(WI)['research/other']} WITH-AI records, so each {100/ch(WI)['research/other']:.1f} in its column here and in Table 4.5 is one record"
m_narr = [r for r in m_un if stub_kind(r) == NARR]
L += ["", f"## WITH-AI {chan_note(WI)}"]
L += table(f"WITH-AI: what did the AI generate: image, voice, text, video or code? {100*len(dk)/len(WI):.0f}% carry only the label 'deepfake', which names no medium; {100*len(m_un)/len(WI):.0f}% unstated, {len(m_un) - len(m_narr)} of those {len(m_un)} tracker stubs",
           WI, val("ai_role"), ci=True, channels=True, num="4.4", note=wi_note, breakdown=prov("ai_role"),
           desc=f"{len(AIROLE)} text rules, then the label. 'deepfake' is not a text pattern because it names no medium, so the value is reached only through the label: of the {len(dk)} deepfake-label records, {len(dk_text)} say 'deepfake' in their own text, "
                f"{len(dk_line)} only in the OECD stub's sentence 'Classified attack vector: deepfake' and {len(dk) - len(dk_text) - len(dk_line)} not at all; none states image, voice or video. The ↳ rows under unstated split the {len(m_un)} remaining records by attack-vector group; "
                f"{len(m_un) - len(m_narr)} are tracker stubs and {ch(m_narr)['cve/ghsa']} of the {len(m_narr)} narrative ones are CVE/GHSA advisories; the conventional-exploit and malicious-package rows are step 2's weak spot (CVE rows in WITH-AI, Table 2.5).")
oc = collections.Counter(M[r["id"]]["objective"] for r in WI); imp = [r for r in WI if M[r["id"]]["objective"] == OBJECTIVE[3][0]]; imp_cve = [r for r in imp if source_class(r) == "cve/ghsa"]
imp_word = collections.Counter(OBJECTIVE[3][1].search(text(r)).group(0).lower() for r in imp_cve).most_common(1)[0][0]
o_un = un("objective"); o_stub = sum(stub_kind(r) != NARR for r in o_un); o_dk = sum(r["attack_vector"] == "deepfake" for r in o_un)
L += table(f"WITH-AI: what was the attacker after? Financial fraud {100*oc[OBJECTIVE[0][0]]/len(WI):.0f}%, political {100*oc[OBJECTIVE[1][0]]/len(WI):.0f}%, {100*oc['unstated']/len(WI):.0f}% state no objective, {o_dk} of them labelled only 'deepfake'",
           WI, val("objective"), ci=True, channels=True, num="4.5", breakdown=prov("objective"),
           desc=f"{len(OBJECTIVE)} text rules, then the label; csam-generation is the only vector that states an objective, so it adds {nlab('objective')} records. The ↳ rows under unstated split the {len(o_un)} remaining by attack-vector group: "
                f"deepfake names what was made, not why, {o_stub} of the {len(o_un)} are tracker stubs, and the conventional-exploit and malicious-package rows are the same step-2 weak spot as in Table 4.4. "
                f"{len(imp_cve)} of the {len(imp)} impersonation records are CVE/GHSA advisories where the attacker impersonates a user or host, a known false positive (under Table 4.7), so that row is too high.")

# ---------------------------------------------------------------- fill rates
L += ["", "## What do the records contain at all?", "",
      f"**Table 4.6. What the records contain: `mitigations` and `impact` are filled on {pct(sum(bool(r.get('mitigations')) for r in ON), len(ON))}% of ON-AI and "
      f"{pct(sum(bool(r.get('mitigations')) for r in WI), len(WI))}% of WITH-AI records** (ON-AI n = {len(ON):,}; WITH-AI n = {len(WI):,})", "",
      "Records in which the field is filled or a value was found (text or label); the complement must be coded from primary references. "
      "`mitigations` and `impact` are the corpus's own notes, not the victim's controls or measured losses.", "",
      "| field | ON-AI filled (n, %) | WITH-AI filled (n, %) | what it holds |", "|---|---|---|---|"]
mit0 = next(r for r in ON if r.get("mitigations")); imp0 = next(r for r in ON if r.get("impact"))
found_what = lambda dim, pop: f"{pop} only: {sum(M[r['id']][dim + '_source'] == 'text' for r in POP[dim]):,} from the text, {nlab(dim):,} from the label"
FIELDS = [("`mitigations`", lambda r: bool(r.get("mitigations")), f"a list of recommended controls, e.g. \"{cut(mit0['mitigations'][0], 36)}\""),
          ("`impact`", lambda r: bool(r.get("impact")), f"free text on consequences, e.g. \"{cut(imp0['impact'], 36)}\""),
          ("`exploited_in_wild` is true", lambda r: r.get("exploited_in_wild") is True, "never false, only true or missing"),
          ("`affected` non-empty", lambda r: bool(r.get("affected")), "product or victim named (Table 4.2 ↳ rows)"),
          ("description is a narrative, not a tracker stub", lambda r: stub_kind(r) == NARR, f"stub forms: Table 4.2; median description {med([len(r['description']) for r in ON])} characters in ON-AI, {med([len(r['description']) for r in WI])} in WITH-AI"),
          ("entry point found (Table 4.1)", lambda r: M[r["id"]]["entry_point"] != "unstated", found_what("entry_point", "ON-AI")),
          ("target component found (Table 4.2)", lambda r: M[r["id"]]["target"] != "unstated", found_what("target", "ON-AI")),
          ("AI medium found (Table 4.4)", lambda r: M[r["id"]]["ai_role"] != "unstated", found_what("ai_role", "WITH-AI")),
          ("attacker objective found (Table 4.5)", lambda r: M[r["id"]]["objective"] != "unstated", found_what("objective", "WITH-AI"))]
ASK = {"entry point found (Table 4.1)": ("ON-AI",), "target component found (Table 4.2)": ("ON-AI",), "AI medium found (Table 4.4)": ("WITH-AI",), "attacker objective found (Table 4.5)": ("WITH-AI",)}
for name, f, what in FIELDS:
    cell = lambda rows, p: (f"{sum(map(f, rows)):,} ({pct(sum(map(f, rows)), len(rows))}%)" if p in ASK.get(name, ("ON-AI", "WITH-AI")) else "—")
    L.append(f"| {name} | {cell(ON, 'ON-AI')} | {cell(WI, 'WITH-AI')} | {what} |")

# ---------------------------------------------------------------- known defects
drows, dmoved = [], 0
for dim, name, what, old, new, fix in DEFECTS:
    P = POP[dim]; oldrules = swap(DIMS[dim], name, new, old); moved = sum(first(oldrules, text(r)) != tv(r, dim) for r in P); dmoved += moved
    drows.append(f"| {DIM_NAME[dim]} {name.split(' (')[0]} | {what} | {fix} | {moved} |")
L += ["", "## Where these rules are known to be wrong", "",
      f"**Table 4.7. {len(DEFECTS)} substring defects fixed with word boundaries moved {dmoved} records to another text value; one known false positive is not fixed** (text tier only)", "",
      "Per fix: the records of the population the dimension is coded on (ON-AI for 4.1–4.2, WITH-AI for 4.4–4.5) whose text-tier value differs between the old substring and the fix; the patterns are in the script.", "",
      "| rule | what the old substring also matched | fix | records whose value changed |", "|---|---|---|---|"]
L += drows
L += ["", f"Not fixed: `{imp_word}` in Table {DIM_NAME['objective']} rule '{OBJECTIVE[3][0]}' matches {len(imp_cve)} CVE/GHSA WITH-AI advisories where the attacker impersonates a user or host; no word boundary separates the two senses; the fix is a read of the source."]
rv = load_rv(); J = join_rv(C, rv)["rows"]
hl = [r for r in ON if source_class(r) == "harm-db" and J.get(r["id"], {}).get("gold_labels") is not None]; ne = [r for r in hl if J[r["id"]]["gold_labels"] == []]
L += ["", f"**Table 4.7b. {len(ne)} of the {len(hl)} harm-database ON-AI records in rank-validation's hand-labelled sample were filed under 'no entry fits'** (n = {len(ne)})", "",
      f"rank-validation's hand-labelled rows (adjudicated OWASP labels, s01 section 0) include {len(hl)} harm-db records in this study's ON-AI; {len(ne)} of them were judged to fit no OWASP entry. "
      "They are fairness evaluations and rights stories carried into ON-AI by a corpus keyword label. What to do first: "
      f"(1) check the {ch(conv)['harm-db']} harm-db records with a conventional-exploit label (Table 4.1) for misfiles, (2) treat every label-derived value on a harm-db record as unconfirmed, (3) exclude where the title confirms the misfile.", "",
      "| id | attack vector | step-2 rule | title |", "|---|---|---|---|"]
L += [f"| {r['id']} | {r['attack_vector']} | {S[r['id']]['rule']} | {cut(r['title'], 40)} |" for r in sorted(ne, key=lambda r: (r["attack_vector"], r["id"]))]

# ---------------------------------------------------------------- appendix: by year
YEARS = range(2022, 2027)
prefix = lambda s: re.match(r"[A-Za-z]+", s).group(0).upper()  # tracker prefix of a source id; AIAAIC ids have no hyphen ('AIAAIC1483')
def year_table(num, pop, rows, dim, key, rules):
    out = sum(not YEARS.start <= r["year"] < YEARS.stop for r in rows); by = {y: [r for r in rows if r["year"] == y] for y in YEARS}
    top = lambda sub: (lambda c: f"{c.most_common(1)[0][0]} ({pct(c.most_common(1)[0][1], len(sub))}%)")(collections.Counter(p for r in sub for p in {prefix(s) for s in r["source_ids"]})) if sub else "—"
    L = ["", f"**Table {num}. {pop} {dim} by record year (% within year; {out} {pop} records from other years left out)** (n = {len(rows) - out:,})", "",
         f"| {dim} | " + " | ".join(f"{y} (n = {len(by[y]):,})" for y in YEARS) + " |", "|---|" + "---|" * len(YEARS),
         "| *most common source prefix* | " + " | ".join(top(by[y]) for y in YEARS) + " |"]
    for v in [n for n, _ in rules] + EXTRA[key] + ["unstated"]:
        L.append(f"| {v} | " + " | ".join(pct(sum(M[r["id"]][key] == v for r in by[y]), len(by[y])) for y in YEARS) + " |")
    return L
L += ["", "## Appendix: shares by record year track tracker ingestion, not time (Table 1.5)", "",
      f"Columns ({YEARS.start}–{YEARS.stop - 1}) sum to 100 within year, text and label values together; the first row is the tracker prefix on most of that year's records."]
L += year_table("4.A1", "ON-AI", ON, "entry point", "entry_point", ENTRY) + year_table("4.A2", "WITH-AI", WI, "AI medium", "ai_role", AIROLE)
write("s04_methodology.md", L)
