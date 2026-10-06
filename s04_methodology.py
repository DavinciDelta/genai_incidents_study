#!/usr/bin/env python3
"""s04_methodology.py — Step 4. Entry point, target, AI medium and objective by keyword rule, for ON-AI and WITH-AI.
Every dimension is a keyword/field rule over title+description+affected; rules are tried in order, first match wins, and
'unstated' = no rule matched. The shares are lower bounds to be replaced by codes from primary references.
Output: out/methodology.json (id → entry_point, target, dependency, ai_role, objective; read by s05) and out/s04_methodology.md
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
# (dimension, rule name, what the old substring also matched, old fragment, new fragment). Table 4.7 recomputes both.
DEFECTS = [("entry_point", ENTRY[0][0], "'document' in 'documentation', 'documented'", r"document", r"\bdocuments?\b"),
           ("target", TARGET[0][0], "'cline' in 'declined'", r"cline", r"\bcline\b"),
           ("target", TARGET[0][0], "'dify' in 'modify'", r"dify", r"\bdify\b"),
           ("target", TARGET[1][0], "'llama' in 'Ollama' (a serving library)", r"llama", r"(?<!o)llama"),
           ("target", TARGET[5][0], "'facial recognition' missed the hyphenated 'facial-recognition'", r"facial recognition", r"facial[- ]recognition"),
           ("ai_role", AIROLE[4][0], "'script' / 'payload' in 'JavaScript', 'HTML payload' (vulnerability advisories)", r"script|payload", CODE_FRAG),
           ("objective", OBJECTIVE[0][0], "'invest' in 'investigation', 'investigative'", r"invest", r"\binvest(ments?|ors?|ing|ed|s)?\b"),
           ("objective", OBJECTIVE[1][0], "'party' in 'third party', 'httparty'", r"party", r"(?<!third[- ])(?<!http)\bparty\b"),
           ("objective", OBJECTIVE[4][0], "'apt' in 'captured', 'capture'", r"apt", r"\bapt\d*\b")]
DIM_NAME = {"entry_point": "entry point (4.1)", "target": "target (4.2)", "ai_role": "AI medium (4.4)", "objective": "objective (4.5)"}
MODEL_VEC = ("prompt-injection", "indirect-prompt-injection", "jailbreak", "adversarial-input", "evasion", "model-extraction", "membership-inference", "model-inversion")
def dep(r):
    if r.get("cve_ids") or r.get("cwe_ids"): return "CVE/CWE present (software vulnerability)"
    if r["attack_vector"] in MODEL_VEC: return "model-level attack vector, no CVE/CWE"
    return "unstated"
DIMS = {"entry_point": ENTRY, "target": TARGET, "ai_role": AIROLE, "objective": OBJECTIVE}
ON = [C[i] for i, s in S.items() if s["population"] == "ON-AI"]; WI = [C[i] for i, s in S.items() if s["population"] == "WITH-AI"]
M = {r["id"]: {**{d: first(rules, text(r)) for d, rules in DIMS.items()}, "dependency": dep(r)} for r in ON + WI}
json.dump(M, open(OUT / "methodology.json", "w"), indent=0); print(f"wrote out/methodology.json ({len(M):,} records)")

# ---------------------------------------------------------------- helpers
POP = {"entry_point": ON, "target": ON, "ai_role": WI, "objective": WI}
pct = lambda a, b: f"{100*a/b:.1f}" if b else "—"
ch = lambda rows: collections.Counter(source_class(r) for r in rows)
med = lambda xs: (sorted(xs)[len(xs) // 2] if xs else 0)
cut = lambda t, k: t if len(t) <= k else t[:k].rsplit(" ", 1)[0] + "…"
def swap(rules, name, new, old):  # the same rule list with one fragment put back to its old form
    return [(n, RX(rx.pattern.replace(new, old)) if n == name else rx) for n, rx in rules]
STUBS = [("OECD pointer stub ('Tracked by the OECD …')", lambda r: r["description"].startswith("Tracked by the OECD")),
         ("AIID title-repeat stub ('AI Incident Database (AIID) entry #N: <title>')", lambda r: r["description"].startswith("AI Incident Database (AIID) entry #")),
         ("AIAAIC facts-only stub ('AIAAIC-tracked incident. Technology: … Sector: …')", lambda r: r["description"].startswith("AIAAIC-tracked incident"))]
NARR = "narrative description"
stub_kind = lambda r: next((k for k, f in STUBS if f(r)), NARR)
# The OECD stub repeats the record's attack_vector label in a 'Classified attack vector: <value>.' sentence; a corpus label never
# populates a coded field, so that sentence is removed before asking whether the source itself says 'deepfake'.
LABEL_LINE = RX(r"Classified attack vector: ([a-z-]+)\.?")
says_deepfake = lambda r: "deepfake" in f"{r['title']} {LABEL_LINE.sub('', r['description'])} {r.get('affected') or ''}".lower()
ENTRY_GROUPS = [("conventional software exploit (rce, ssrf, injection, xss, dos, …)",
                 {"rce", "ssrf", "sql-injection", "command-injection", "path-traversal", "deserialization", "xss", "auth-bypass", "info-disclosure", "dos", "csrf", "data-exfiltration"}),
                ("malicious package / backdoor / supply chain", {"malware", "supply-chain", "backdoor"}),
                ("prompt injection / jailbreak", {"prompt-injection", "indirect-prompt-injection", "jailbreak"}),
                ("adversarial input / evasion / inference attacks", {"adversarial-input", "evasion", "membership-inference", "model-extraction", "model-inversion"}),
                ("agent / sandbox / tool abuse", {"sandbox-escape", "tool-abuse", "agent-hijack", "memory-poisoning"}),
                ("training / model poisoning", {"model-poisoning"})]
OTHER_G = "'other' and harm-type vectors (misinformation, unsafe-advice, …)"
egroup = lambda r: next((g for g, vs in ENTRY_GROUPS if r["attack_vector"] in vs), OTHER_G)
OUTSIDE, SILENT = {ENTRY_GROUPS[i][0] for i in (0, 4, 5)}, {ENTRY_GROUPS[i][0] for i in (1, 2, 3)}  # no vocabulary value / value exists, keywords absent
chan_note = lambda P: "(" + ", ".join(f"{x} {ch(P)[x]:,}" for x in CHANNELS) + " records; channel columns are % of that channel)"

# ---------------------------------------------------------------- ON-AI
e_un = [r for r in ON if M[r["id"]]["entry_point"] == "unstated"]; gc = collections.Counter(egroup(r) for r in e_un); rc = collections.Counter(S[r["id"]]["rule"] for r in e_un)
pi = [r for r in e_un if egroup(r) == ENTRY_GROUPS[2][0]]; conv = [r for r in e_un if egroup(r) == ENTRY_GROUPS[0][0]]
labelled = lambda i: [r for r in ON if r["attack_vector"] in ENTRY_GROUPS[i][1]]; found = lambda i, rule: sum(M[r["id"]]["entry_point"] == rule for r in labelled(i))
ag = [r for r in ON if M[r["id"]]["target"] == TARGET[0][0]]; bare = [r for r in ag if not RX(TARGET[0][1].pattern.replace(r"\bagent|", "")).search(text(r))]
noise = sum(bool(RX(r"user[- ]agent|threat agent|agentless").search(text(r))) for r in bare); ai_ag = sum(bool(RX(r"(ai|llm|coding|autonomous) agents?|agentic").search(text(r))) for r in bare)
both_dep = sum(bool(r.get("cve_ids") or r.get("cwe_ids")) and r["attack_vector"] in MODEL_VEC for r in ON); dc = collections.Counter(dep(r) for r in ON)
assert {source_class(r) for r in ON if r.get("cve_ids") or r.get("cwe_ids")} == {"cve/ghsa"} and not any((r.get("cve_ids") or r.get("cwe_ids")) and source_class(r) != "cve/ghsa" for r in ON)
L = ["# Step 4 — Entry point, target, AI medium and objective by keyword rule (what hand-coding must resolve)", "",
     "Generated by `s04_methodology.py` (`make s04`); do not edit by hand. Keyword rules over the title + description + affected text give each "
     "ON-AI record an entry point and a target component and each WITH-AI record an AI medium and an attacker objective; a read of corpus fields gives ON-AI a CVE/CWE flag. "
     "`unstated` = no rule matched. Under every unstated row of Tables 4.1–4.5, indented ↳ rows say what those records are, read from corpus fields only "
     "(the attack-vector label, whether `affected` is filled, the description's opening words), never from a new rule, and sort the hand-coding work into three kinds: text naming something the vocabulary has no value for (extend the vocabulary), "
     "text silent or ambiguous (read primary references), tracker stub (go to the source tracker). The exact fragments are the `ENTRY`, `TARGET`, `AIROLE` and `OBJECTIVE` lists at the top of the script; "
     "the per-record values (id → entry_point, target, dependency, ai_role, objective) are `out/methodology.json`.", "", READ,
     f"", f"## ON-AI {chan_note(ON)}: how did the adversary reach the AI system, what was attacked, and was a software bug involved?"]
L += table(f"ON-AI: how did the adversary first reach the AI system? {100*len(e_un)/len(ON):.0f}% match no rule; {len(conv)} of those carry a conventional-exploit attack-vector label", ON, lambda r: M[r["id"]]["entry_point"], ci=True, channels=True, num="4.1", breakdown=("unstated", egroup),
           note=f"The corpus labels {len(labelled(1))} ON-AI records malware / supply-chain / backdoor and the supply-chain rule finds {found(1, ENTRY[2][0])} of them, labels {len(labelled(3))} adversarial / evasion / inference and the adversarial-input rule finds {found(3, ENTRY[5][0])}, so the found shares are floors",
           desc=f"Six keyword rules over the title + description + affected text, first match wins; unstated = no rule matched. The ↳ rows split the {len(e_un)} unstated records by the corpus's own attack-vector label (a corpus label, not a new rule): the exploit, agent / sandbox and poisoning groups "
                f"({sum(v for g, v in gc.items() if g in OUTSIDE)} records) name a mechanism the entry-point vocabulary has no value for (a conventional software exploit has no 'entry point' value), so they are outside the vocabulary rather than silent, while the supply-chain, prompt-injection and adversarial groups "
                f"({sum(v for g, v in gc.items() if g in SILENT)}) have a value whose keywords the text lacks ({sum(stub_kind(r) != NARR for r in pi)} of the {len(pi)} prompt-injection records are tracker stubs and {sum('prompt' in text(r).lower() for r in pi)} say 'prompt' in a phrase no rule lists), so the source must be read. "
                f"Step 2 placed {rc['conventional-exploit-of-ai-tooling']} of the {len(e_un)} in ON-AI by its conventional-exploit rule (attacker word + code vector, Table 2.4), {rc['on-vector']} by on-vector and {rc['on-vocabulary']} by on-vocabulary; "
                f"{ch(conv)['harm-db']} of the {len(conv)} exploit-labelled records are harm-db records whose label is a corpus keyword, so expect misfiles (Table 4.7b).")
t_un = [r for r in ON if M[r["id"]]["target"] == "unstated"]
T_STUB, T_OUT, T_NONE = "tracker stub, no system named in the text (OECD / AIID / AIAAIC form)", "names a product in `affected` that the six lists do not cover (target stated, list gap)", "names no system (`affected` empty)"
tkind = lambda r: T_STUB if stub_kind(r) != NARR else (T_OUT if r.get("affected") else T_NONE)
t_out = collections.Counter(r["affected"] for r in t_un if tkind(r) == T_OUT); top5 = sorted(t_out.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:5]
tied = sum(v == top5[-1][1] for v in t_out.values()) - sum(v == top5[-1][1] for _, v in top5); prai = sum(v for a, v in t_out.items() if "praison" in a.lower())
L += table(f"ON-AI: which part of the AI stack was attacked? Agents, copilots and MCP in {100*len(ag)/len(ON):.0f}%, and {100*ch(ag)['cve/ghsa']/len(ag):.0f}% of those {len(ag)} are CVE/GHSA records; {100*len(t_un)/len(ON):.0f}% unstated, of which {100*sum(t_out.values())/len(t_un):.0f}% name a product the lists do not cover",
           ON, lambda r: M[r["id"]]["target"], ci=True, channels=True, num="4.2", breakdown=("unstated", tkind),
           desc="The record's title, description and affected text is searched for product and component names in six lists, first matching list wins: "
                "agent / copilot / cursor / mcp …; chatgpt / gemini / claude / chatbot …; langchain / vllm / ollama / pytorch …; vector db / embedding / pinecone …; hugging face / weights / fine-tun …; detector / classifier / facial recognition …. "
                f"{len(bare)} of the {len(ag)} agent records match only the bare word 'agent': {noise or 'none'} in the 'user agent' / 'threat agent' sense, {ai_ag} say 'AI', 'LLM', 'coding' or 'autonomous agent' or 'agentic'. "
                f"The ↳ rows split the {len(t_un)} unstated records by corpus fields: a description opening with a tracker stub form ('Tracked by the OECD …', 'AI Incident Database (AIID) entry #…', 'AIAAIC-tracked incident …'; per form in Table 4.4), else whether `affected` is filled; "
                f"the most frequent `affected` values among the {sum(t_out.values())} 'list gap' records are {', '.join(f'{cut(a, 40)} ({k})' for a, k in top5)} ({tied} more tied at {top5[-1][1]}; PraisonAI has two spellings, {prai} records): "
                "the target is stated, the lists are short. Four substring defects in these lists are counted in Table 4.7.")
CVE, MV = "CVE/CWE present (software vulnerability)", "model-level attack vector, no CVE/CWE"; d_un = [r for r in ON if dep(r) == "unstated"]
L += table(f"ON-AI: does the record carry a CVE/CWE ({100*dc[CVE]/len(ON):.0f}%), a model-level attack vector ({100*dc[MV]/len(ON):.0f}%) or neither ({100*dc['unstated']/len(ON):.0f}%)?", ON, dep, ci=True, num="4.3", breakdown=("unstated", egroup),
           desc="Read off corpus fields (a CVE or CWE id, else a model-level attack vector: prompt injection, jailbreak, adversarial input, evasion, model extraction or inversion, membership inference; else unstated = neither set); no channel columns because every CVE/CWE record is in the cve/ghsa channel and no other channel has one. "
                f"The ↳ rows split the {len(d_un)} unstated records by attack-vector label as in Table 4.1 (harm-db {ch(d_un)['harm-db']}, research/other {ch(d_un)['research/other']}; {sum(stub_kind(r) != NARR for r in d_un)} tracker stubs). "
                f"{both_dep} records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor, and `exploited_in_wild` is set on {sum(r.get('exploited_in_wild') is True for r in ON)} ON-AI records (Table 4.6), so nothing here says whether an attack succeeded.")

# ---------------------------------------------------------------- WITH-AI
m_un = [r for r in WI if M[r["id"]]["ai_role"] == "unstated"]; dk = [r for r in m_un if says_deepfake(r)]
dk_label = [r for r in m_un if "deepfake" in text(r).lower() and not says_deepfake(r)]  # the word appears only in the OECD label line
assert all(LABEL_LINE.search(r["description"]).group(1) == r["attack_vector"] for r in dk_label)
wi_note = f"research/other has {ch(WI)['research/other']} WITH-AI records, so each {100/ch(WI)['research/other']:.1f} in its column is one record"
m_narr = [r for r in m_un if stub_kind(r) == NARR]
L += ["", f"## WITH-AI {chan_note(WI)}: what did the AI make for the attacker, and what was the attacker after?"]
aia_med = med([len(r["description"]) for r in m_un if stub_kind(r) == STUBS[2][0]])
L += table(f"WITH-AI: what did the AI generate: image, voice, text, video or code? {100*len(m_un)/len(WI):.0f}% name no medium, and {len(m_un) - len(m_narr)} of those {len(m_un)} are tracker stubs", WI, lambda r: M[r["id"]]["ai_role"], ci=True, channels=True, num="4.4", note=wi_note, breakdown=("unstated", stub_kind),
           desc=f"Six medium rules over the title + description + affected text, first match wins; unstated = no rule matched. The ↳ rows split the {len(m_un)} unstated records by their description's opening words: a stub carries a tracker id, the title or the corpus's own attack-vector label, so no rule can read a medium from it; "
                f"{ch(m_narr)['cve/ghsa']} of the {len(m_narr)} narrative records are CVE/GHSA advisories (step 2's weak spot, Table 2.5). "
                f"{sum(r['attack_vector'] == 'deepfake' for r in m_un)} of the {len(m_un)} carry the deepfake attack vector, {len(dk)} say 'deepfake' in their own text ({len(dk_label)} more only in the OECD stub's label sentence 'Classified attack vector: deepfake', not counted) "
                f"and the AIAAIC stubs have a median description of {aia_med} characters; 'deepfake' names no medium (image, voice or video), so these stay unstated and a coder needs a 'deepfake, medium not stated' value or the source.")
oc = collections.Counter(M[r["id"]]["objective"] for r in WI); imp = [r for r in WI if M[r["id"]]["objective"] == OBJECTIVE[3][0]]; imp_cve = [r for r in imp if source_class(r) == "cve/ghsa"]
imp_word = collections.Counter(OBJECTIVE[3][1].search(text(r)).group(0).lower() for r in imp_cve).most_common(1)[0][0]
o_un = [r for r in WI if M[r["id"]]["objective"] == "unstated"]
o_stub = sum(stub_kind(r) != NARR for r in o_un); o_dk = sum(r["attack_vector"] == "deepfake" for r in o_un)
L += table(f"WITH-AI: what was the attacker after? Financial fraud {100*oc[OBJECTIVE[0][0]]/len(WI):.0f}%, political {100*oc[OBJECTIVE[1][0]]/len(WI):.0f}%, {100*oc['unstated']/len(WI):.0f}% state no objective the rules recognise", WI, lambda r: M[r["id"]]["objective"], ci=True, channels=True, num="4.5", note=wi_note, breakdown=("unstated", stub_kind),
           desc=f"Five keyword rules over the same text, first match wins; unstated = no rule matched. The ↳ rows split the {len(o_un)} unstated records by description kind as in Table 4.4: {o_stub} of the {len(o_un)} are tracker stubs and {o_dk} carry the deepfake attack vector. "
                f"{len(imp_cve)} of the {len(imp)} impersonation records are CVE/GHSA advisories matched on the word "
                f"'{imp_word}' (an attacker impersonating a user or host, not a person being impersonated): a known false positive, not fixed (under Table 4.7), so the row's share and CI are too high.")

# ---------------------------------------------------------------- fill rates
L += ["", "## What do the records contain at all?", "",
      f"**Table 4.6. What the records contain for attacker analysis: `mitigations` and `impact` are filled on {pct(sum(bool(r.get('mitigations')) for r in ON), len(ON))}% of ON-AI and "
      f"{pct(sum(bool(r.get('mitigations')) for r in WI), len(WI))}% of WITH-AI records** (ON-AI n = {len(ON):,}; WITH-AI n = {len(WI):,})", "",
      "Records in which the field is filled or a rule found a value; the complement is what has to be coded from primary references. "
      "`mitigations` and `impact` are the corpus's own recommendations and summaries, not controls the victim had or measured losses.", "",
      "| field | ON-AI filled (n, %) | WITH-AI filled (n, %) | what it holds |", "|---|---|---|---|"]
mit0 = next(r for r in ON if r.get("mitigations")); imp0 = next(r for r in ON if r.get("impact"))
FIELDS = [("`mitigations`", lambda r: bool(r.get("mitigations")), f"a list of recommended controls, e.g. \"{cut(mit0['mitigations'][0], 50)}\""),
          ("`impact`", lambda r: bool(r.get("impact")), f"free text on consequences, e.g. \"{cut(imp0['impact'], 50)}\""),
          ("`discovery_method`", lambda r: bool(r.get("discovery_method")), "values: " + ", ".join(f"{k} {v}" for k, v in collections.Counter(r.get("discovery_method") for r in ON + WI if r.get("discovery_method")).most_common())),
          ("`exploited_in_wild` is true", lambda r: r.get("exploited_in_wild") is True, "never false, only true or missing"),
          ("`affected` non-empty", lambda r: bool(r.get("affected")), "product or victim named (Table 4.2 ↳ rows)"),
          ("description is a narrative, not a tracker stub", lambda r: stub_kind(r) == NARR, f"stub kinds: ↳ rows of Table 4.4; median description {med([len(r['description']) for r in ON])} characters in ON-AI, {med([len(r['description']) for r in WI])} in WITH-AI"),
          ("entry point found (Table 4.1)", lambda r: M[r["id"]]["entry_point"] != "unstated", "ON-AI rule; WITH-AI not asked"),
          ("target component found (Table 4.2)", lambda r: M[r["id"]]["target"] != "unstated", "ON-AI rule; WITH-AI not asked"),
          ("AI medium found (Table 4.4)", lambda r: M[r["id"]]["ai_role"] != "unstated", "WITH-AI rule; ON-AI not asked"),
          ("attacker objective found (Table 4.5)", lambda r: M[r["id"]]["objective"] != "unstated", "WITH-AI rule; ON-AI not asked")]
ASK = {"entry point found (Table 4.1)": ("ON-AI",), "target component found (Table 4.2)": ("ON-AI",), "AI medium found (Table 4.4)": ("WITH-AI",), "attacker objective found (Table 4.5)": ("WITH-AI",)}
for name, f, what in FIELDS:
    cell = lambda rows, p: (f"{sum(map(f, rows)):,} ({pct(sum(map(f, rows)), len(rows))}%)" if p in ASK.get(name, ("ON-AI", "WITH-AI")) else "—")
    L.append(f"| {name} | {cell(ON, 'ON-AI')} | {cell(WI, 'WITH-AI')} | {what} |")

# ---------------------------------------------------------------- known defects
drows, dmoved = [], 0
for dim, name, what, old, new in DEFECTS:
    P = POP[dim]; o = {r["id"] for r in P if RX(old).search(text(r))}; n = {r["id"] for r in P if RX(new).search(text(r))}
    oldrules = swap(DIMS[dim], name, new, old); moved = sum(first(oldrules, text(r)) != M[r["id"]][dim] for r in P); dmoved += moved
    drows.append(f"| {DIM_NAME[dim]} | {name} | {what} | `{old}` | {'`CODE_FRAG` in the script (' + str(len(new)) + ' characters)' if new == CODE_FRAG else f'`{new}`'} | {len(o - n)} | {len(n - o)} | {moved} |")
L += ["", "## Where these rules are known to be wrong", "",
      f"**Table 4.7. {len(DEFECTS)} substring defects fixed with word boundaries moved {dmoved} records to another value; one known false positive is not fixed** ({len(DEFECTS)} fixes)", "",
      "For each fix, the records of the rule's population that the old fragment matched and the new one does not (and vice versa), and the records whose value changed; "
      "a fragment match does not always change the value because an earlier rule or another word in the same rule may still fire; every count is recomputed on each run.", "",
      "| dimension | rule | what the old substring also matched | old fragment | new fragment | old matched, new does not | new matched, old does not | records whose value changed |", "|---|---|---|---|---|---|---|---|"]
L += drows
L += ["", f"Not fixed: `{imp_word}` in the {DIM_NAME['objective']} rule '{OBJECTIVE[3][0]}' matches {len(imp_cve)} CVE/GHSA WITH-AI advisories where the attacker impersonates a user or host; no word boundary separates the two senses; the fix is a read of the source."]
rv = load_rv(); J = join_rv(C, rv)["rows"]
hl = [r for r in ON if source_class(r) == "harm-db" and J.get(r["id"], {}).get("gold_labels") is not None]; ne = [r for r in hl if J[r["id"]]["gold_labels"] == []]
L += ["", f"**Table 4.7b. {len(ne)} of the {len(hl)} harm-database ON-AI records in rank-validation's hand-labelled sample were filed under 'no entry fits'** (n = {len(ne)})", "",
      "The hand labels are rank-validation's adjudicated OWASP labels (s01 section 0); an empty list = no entry fits. Step-2 rules (Table 2.4): `on-vector` = corpus attack vector in the ON list, "
      "`on-vocabulary` = ON text pattern, `conventional-exploit-of-ai-tooling` = attacker word plus a conventional code vector. Fairness evaluations, rights stories and other records carried into ON-AI by a corpus keyword label: "
      f"review before coding and exclude where the title confirms the misfile; the {ch(conv)['harm-db']} harm-db records with a conventional-exploit label (Table 4.1) are suspect for the same reason.", "",
      "| id | attack vector | step-2 rule | title |", "|---|---|---|---|"]
L += [f"| {r['id']} | {r['attack_vector']} | {S[r['id']]['rule']} | {cut(r['title'], 70)} |" for r in sorted(ne, key=lambda r: (r["attack_vector"], r["id"]))]

# ---------------------------------------------------------------- appendix: by year
YEARS = range(2022, 2027)
prefix = lambda s: re.match(r"[A-Za-z]+", s).group(0).upper()  # tracker prefix of a source id; AIAAIC ids have no hyphen ('AIAAIC1483')
def year_table(num, pop, rows, dim, key, rules):
    out = sum(not YEARS.start <= r["year"] < YEARS.stop for r in rows); by = {y: [r for r in rows if r["year"] == y] for y in YEARS}
    top = lambda sub: (lambda c: f"{c.most_common(1)[0][0]} ({pct(c.most_common(1)[0][1], len(sub))}%)")(collections.Counter(p for r in sub for p in {prefix(s) for s in r["source_ids"]})) if sub else "—"
    L = ["", f"**Table {num}. {pop} {dim} by record year (% within year; {out} {pop} records from other years left out)** (n = {len(rows) - out:,})", "",
         f"| {dim} | " + " | ".join(f"{y} (n = {len(by[y]):,})" for y in YEARS) + " |", "|---|" + "---|" * len(YEARS),
         "| *most common source prefix* | " + " | ".join(top(by[y]) for y in YEARS) + " |"]
    for v in [n for n, _ in rules] + ["unstated"]:
        L.append(f"| {v} | " + " | ".join(pct(sum(M[r["id"]][key] == v for r in by[y]), len(by[y])) for y in YEARS) + " |")
    return L
L += ["", "## Appendix: shares by record year track which tracker was ingested that year, not time (Table 1.5)", "",
      f"Columns are record years {YEARS.start}–{YEARS.stop - 1}, each summing to 100; the first row names the tracker prefix on most of that year's records."]
L += year_table("4.A1", "ON-AI", ON, "entry point", "entry_point", ENTRY) + year_table("4.A2", "WITH-AI", WI, "AI medium", "ai_role", AIROLE)
write("s04_methodology.md", L)
