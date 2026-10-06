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
           ("target", TARGET[1][0], "'llama' in 'Ollama' (a serving library, caught before the framework rule)", r"llama", r"(?<!o)llama"),
           ("target", TARGET[5][0], "'facial recognition' missed the hyphenated 'facial-recognition'", r"facial recognition", r"facial[- ]recognition"),
           ("ai_role", AIROLE[4][0], "'script' / 'payload' in 'JavaScript', 'HTML payload' (vulnerability advisories)", r"script|payload", CODE_FRAG),
           ("objective", OBJECTIVE[0][0], "'invest' in 'investigation', 'investigative'", r"invest", r"\binvest(ments?|ors?|ing|ed|s)?\b"),
           ("objective", OBJECTIVE[1][0], "'party' in 'third party', 'httparty'", r"party", r"(?<!third[- ])(?<!http)\bparty\b"),
           ("objective", OBJECTIVE[4][0], "'apt' in 'captured', 'capture'", r"apt", r"\bapt\d*\b")]
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
chcells = lambda rows: " | ".join(f"{ch(rows)[x]:,}" for x in CHANNELS)
med = lambda xs: (sorted(xs)[len(xs) // 2] if xs else 0)
def swap(rules, name, new, old):  # the same rule list with one fragment put back to its old form
    return [(n, RX(rx.pattern.replace(new, old)) if n == name else rx) for n, rx in rules]
STUBS = [("OECD pointer stub ('Tracked by the OECD AI Incidents and Hazards Monitor … see the AIM incident page')", lambda r: r["description"].startswith("Tracked by the OECD")),
         ("AIID title-repeat stub ('AI Incident Database (AIID) entry #N: <title>. Alleged deployer/developer: …')", lambda r: r["description"].startswith("AI Incident Database (AIID) entry #")),
         ("AIAAIC facts-only stub ('AIAAIC-tracked incident. Technology: … Sector: … Jurisdiction: …')", lambda r: r["description"].startswith("AIAAIC-tracked incident"))]
stub_kind = lambda r: next((k for k, f in STUBS if f(r)), "narrative description")
# The OECD stub repeats the record's attack_vector label in a 'Classified attack vector: <value>.' sentence; a corpus label never
# populates a coded field, so that sentence is removed before asking whether the source itself says 'deepfake'.
LABEL_LINE = RX(r"Classified attack vector: ([a-z-]+)\.?")
says_deepfake = lambda r: "deepfake" in f"{r['title']} {LABEL_LINE.sub('', r['description'])} {r.get('affected') or ''}".lower()
ENTRY_GROUPS = [("conventional software exploit (rce, ssrf, injection, path traversal, auth bypass, xss, dos, deserialization, info disclosure, data exfiltration)",
                 {"rce", "ssrf", "sql-injection", "command-injection", "path-traversal", "deserialization", "xss", "auth-bypass", "info-disclosure", "dos", "csrf", "data-exfiltration"}),
                ("malicious package / backdoor / supply chain (malware, supply-chain, backdoor)", {"malware", "supply-chain", "backdoor"}),
                ("prompt injection / jailbreak", {"prompt-injection", "indirect-prompt-injection", "jailbreak"}),
                ("adversarial input / evasion / inference attacks (adversarial-input, evasion, membership-inference, model-extraction, model-inversion)", {"adversarial-input", "evasion", "membership-inference", "model-extraction", "model-inversion"}),
                ("agent / sandbox / tool abuse (sandbox-escape, tool-abuse, agent-hijack, memory-poisoning)", {"sandbox-escape", "tool-abuse", "agent-hijack", "memory-poisoning"}),
                ("training / model poisoning", {"model-poisoning"})]
egroup = lambda r: next((g for g, vs in ENTRY_GROUPS if r["attack_vector"] in vs), "'other' (the corpus's own value) and harm-type vectors (misinformation, unsafe-advice, …)")

# ---------------------------------------------------------------- ON-AI
e_un = [r for r in ON if M[r["id"]]["entry_point"] == "unstated"]; ind = [r for r in ON if M[r["id"]]["entry_point"] == ENTRY[0][0]]; dirp = [r for r in ON if M[r["id"]]["entry_point"] == ENTRY[1][0]]
ag = [r for r in ON if M[r["id"]]["target"] == TARGET[0][0]]; bare = sum(not RX(TARGET[0][1].pattern.replace(r"\bagent|", "")).search(text(r)) for r in ag)
both_dep = sum(bool(r.get("cve_ids") or r.get("cwe_ids")) and r["attack_vector"] in MODEL_VEC for r in ON); dc = collections.Counter(dep(r) for r in ON)
assert {source_class(r) for r in ON if r.get("cve_ids") or r.get("cwe_ids")} == {"cve/ghsa"} and not any((r.get("cve_ids") or r.get("cwe_ids")) and source_class(r) != "cve/ghsa" for r in ON)
L = ["# Step 4 — Entry point, target, AI medium and objective by keyword rule (what hand-coding must resolve)", "",
     "Generated by `s04_methodology.py` (`make s04`); do not edit by hand. Keyword rules over the title + description + affected text give each "
     "ON-AI record an entry point and a target component, each WITH-AI record an AI medium and an attacker objective, and a read of corpus fields "
     "gives ON-AI a CVE/CWE flag; the frequency tables show the share within each disclosure channel and an `unstated` row that sizes the hand-coding "
     "workload. The last section lists where the rules are known to be wrong, with the records each defect moved. This step answers *how* an attack happened as far as the record's text says; step 5 answers which OWASP categories stand out against the expert vote and which ATLAS mitigations address them, and repeats none of these tables.", "", READ,
     "", "## ON-AI: how did the adversary reach the AI system, what was attacked, and was a software bug involved?"]
L += table(f"ON-AI: how did the adversary first reach the AI system? {100*len(e_un)/len(ON):.0f}% of records match no rule", ON, lambda r: M[r["id"]]["entry_point"], ci=True, channels=True, num="4.1",
           desc=f"Six keyword rules. Of the {len(ind)} indirect-carrier records {ch(ind)['cve/ghsa']} are CVE/GHSA and {ch(ind)['harm-db']} harm-db, while the {len(dirp)} direct-prompt records come from every channel (harm-db {ch(dirp)['harm-db']}, research/other {ch(dirp)['research/other']}, cve/ghsa {ch(dirp)['cve/ghsa']}); Table 4.1b shows what the unstated row carries.")
gc = collections.Counter(egroup(r) for r in e_un); conv = sum(S[r["id"]]["rule"] == "conventional-exploit-of-ai-tooling" for r in e_un)
L += ["", f"**Table 4.1b. What 'unstated' entry point hides: {gc[ENTRY_GROUPS[0][0]]} conventional software exploits, {gc[ENTRY_GROUPS[1][0]]} malicious packages or backdoors, "
      f"{gc[ENTRY_GROUPS[2][0]]} prompt injections or jailbreaks, {gc[ENTRY_GROUPS[3][0]]} adversarial inputs** (n = {len(e_un):,})", "",
      f"The {len(e_un):,} ON-AI records matching no entry-point rule, grouped by the corpus attack vector. Most name a mechanism the rule vocabulary has no value for "
      f"(there is no 'software exploit' entry point) rather than saying nothing; {conv} of them entered ON-AI through step 2's conventional-exploit rule.", "",
      "| attack vector group | records | % of unstated | cve/ghsa | harm-db | research/other | entered by the conventional-exploit rule |", "|---|---|---|---|---|---|---|"]
for g, _ in sorted(gc.items(), key=lambda kv: -kv[1]):
    sub = [r for r in e_un if egroup(r) == g]
    L.append(f"| {g} | {len(sub):,} | {pct(len(sub), len(e_un))} | {chcells(sub)} | {sum(S[r['id']]['rule'] == 'conventional-exploit-of-ai-tooling' for r in sub)} |")
L += table(f"ON-AI: which part of the AI stack was attacked? Agents, copilots and MCP in {100*len(ag)/len(ON):.0f}%, {100*ch(ag)['cve/ghsa']/len(ag):.0f}% of them CVE/GHSA records", ON, lambda r: M[r["id"]]["target"], ci=True, channels=True, num="4.2",
           desc=f"Six product-name and keyword rules; {bare} of the {len(ag)} agent records match only the bare word 'agent'. The substring defects fixed with word boundaries ('cline' in 'declined', 'dify' in 'modify', 'Ollama' caught as 'llama', the hyphenated 'facial-recognition') are counted in Table 4.7.")
CVE, MV = "CVE/CWE present (software vulnerability)", "model-level attack vector, no CVE/CWE"
L += table(f"ON-AI: does the record carry a CVE/CWE ({100*dc[CVE]/len(ON):.0f}%), a model-level attack vector ({100*dc[MV]/len(ON):.0f}%) or neither ({100*dc['unstated']/len(ON):.0f}%)?", ON, dep, ci=True, num="4.3",
           desc="Read off corpus fields (a CVE or CWE id, else a model-level attack vector: prompt injection, jailbreak, adversarial input, evasion, model extraction or inversion, membership inference; else unstated), with no channel columns because every CVE/CWE record is in the cve/ghsa channel and no other channel has one. "
                f"{both_dep} records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor, and `exploited_in_wild` is set on {sum(r.get('exploited_in_wild') is True for r in ON)} ON-AI records (Table 4.6), so nothing here says whether an attack succeeded.")

# ---------------------------------------------------------------- WITH-AI
m_un = [r for r in WI if M[r["id"]]["ai_role"] == "unstated"]; dk = [r for r in m_un if says_deepfake(r)]
dk_label = [r for r in m_un if "deepfake" in text(r).lower() and not says_deepfake(r)]  # the word appears only in the OECD label line
assert all(LABEL_LINE.search(r["description"]).group(1) == r["attack_vector"] for r in dk_label)
ro_note = lambda: f"research/other has {ch(WI)['research/other']} WITH-AI records, so each {100/ch(WI)['research/other']:.1f} in its column is one record"
orig = [r for r in WI if r.get("description_provenance") == "original"]; ofo = sum(r["description"].startswith("AIAAIC-tracked incident") for r in orig); sk = collections.Counter(stub_kind(r) for r in m_un)
L += ["", "## WITH-AI: what did the AI make for the attacker, and what was the attacker after?"]
L += table(f"WITH-AI: what did the AI generate: image, voice, text, video or code? {100*len(m_un)/len(WI):.0f}% name no medium, and {len(dk)} of those {len(m_un)} say 'deepfake' without one", WI, lambda r: M[r["id"]]["ai_role"], ci=True, channels=True, num="4.4", note=ro_note(),
           desc=f"Six medium rules; the unstated row means medium unspecified rather than silence: {sum(r['attack_vector'] == 'deepfake' for r in m_un)} of the {len(m_un)} carry the deepfake attack vector and {len(dk)} say 'deepfake' in their own title, description or affected text, while {len(dk_label)} more contain the word only in the OECD stub's 'Classified attack vector: deepfake' sentence, which repeats the record's attack_vector label and is not counted. {ch(m_un)['harm-db']} of the {len(m_un)} are harm-database records, and Table 4.4b shows what their descriptions are.")
L += ["", f"**Table 4.4b. What 'unstated' AI medium hides: {sk[STUBS[0][0]] + sk[STUBS[1][0]]} tracker stubs that point to the source or repeat the title, {sk[STUBS[2][0]]} AIAAIC facts-only stubs, {sk['narrative description']} narrative descriptions** (n = {len(m_un):,})", "",
      f"The {len(m_un):,} WITH-AI records matching no medium rule, by what their description is; a stub carries a tracker id, the corpus's own attack-vector label or the title, so no rule can read a medium from it. "
      f"{len(orig)} WITH-AI records have `description_provenance == 'original'` (median {med([len(r['description']) for r in orig])} characters); {'all ' if ofo == len(orig) else ''}{ofo} start with 'AIAAIC-tracked incident', the facts-only form the corpus build script describes for AIAAIC entries (`_aiaaic_seed_text`), and {sum(r in m_un for r in orig)} of the {len(orig)} are in this table.", "",
      "| description kind | records | % of unstated | say 'deepfake' (label sentence excluded) | median description chars | cve/ghsa | harm-db | research/other |", "|---|---|---|---|---|---|---|---|"]
for k in [s[0] for s in STUBS] + ["narrative description"]:
    sub = [r for r in m_un if stub_kind(r) == k]
    L.append(f"| {k} | {len(sub):,} | {pct(len(sub), len(m_un))} | {sum(says_deepfake(r) for r in sub)} | {med([len(r['description']) for r in sub])} | {chcells(sub)} |")
oc = collections.Counter(M[r["id"]]["objective"] for r in WI); imp = [r for r in WI if M[r["id"]]["objective"] == OBJECTIVE[3][0]]; imp_cve = [r for r in imp if source_class(r) == "cve/ghsa"]
fin = [r for r in WI if M[r["id"]]["objective"] == OBJECTIVE[0][0]]; o_un = [r for r in WI if M[r["id"]]["objective"] == "unstated"]
L += table(f"WITH-AI: what was the attacker after? Financial fraud {100*oc[OBJECTIVE[0][0]]/len(WI):.0f}%, political {100*oc[OBJECTIVE[1][0]]/len(WI):.0f}%, {100*oc['unstated']/len(WI):.0f}% state no objective the rules recognise", WI, lambda r: M[r["id"]]["objective"], ci=True, channels=True, num="4.5", note=ro_note(),
           desc=f"Five keyword rules; harm-db holds {ch(fin)['harm-db']} of the {len(fin)} financial-fraud and {ch(o_un)['harm-db']} of the {len(o_un)} unstated records. {len(imp_cve)} of the {len(imp)} impersonation records are CVE/GHSA advisories matched on the word "
                f"'{collections.Counter(OBJECTIVE[3][1].search(text(r)).group(0).lower() for r in imp_cve).most_common(1)[0][0]}' (an attacker impersonating a user or host, not a person being impersonated); the substring defects fixed with word boundaries ('invest' in 'investigation', 'party' in 'third party', 'apt' in 'captured') are counted in Table 4.7.")

# ---------------------------------------------------------------- fill rates
L += ["", "## What do the records contain at all?", "",
      f"**Table 4.6. What the records contain for attacker analysis: `mitigations` and `impact` are filled on {pct(sum(bool(r.get('mitigations')) for r in ON), len(ON))}% of ON-AI and "
      f"{pct(sum(bool(r.get('mitigations')) for r in WI), len(WI))}% of WITH-AI records** (ON-AI n = {len(ON):,}; WITH-AI n = {len(WI):,})", "",
      "Each row is the number and share of records in which the field is filled or a rule found a value; the complement is what has to be coded from primary references. "
      "`mitigations` and `impact` are the corpus's own recommendations and summaries, not controls the victim had or measured losses.", "",
      "| field | ON-AI filled (n, %) | WITH-AI filled (n, %) | what it holds |", "|---|---|---|---|"]
cut = lambda t, k: t if len(t) <= k else t[:k].rsplit(" ", 1)[0] + "…"
def lead(rows):  # (most common opening two words, its count, n) over a population's description_provenance == 'original' records
    c = collections.Counter(" ".join(r["description"].split()[:2]) for r in rows if r.get("description_provenance") == "original"); w, k = c.most_common(1)[0]; return w, k, sum(c.values())
mit0 = next(r for r in ON if r.get("mitigations")); imp0 = next(r for r in ON if r.get("impact"))
assert not any(r.get("cvss_score") is not None and source_class(r) != "cve/ghsa" for r in ON + WI)
FIELDS = [("`mitigations`", lambda r: bool(r.get("mitigations")), f"a list of recommended controls, e.g. \"{cut(mit0['mitigations'][0], 70)}\""),
          ("`impact`", lambda r: bool(r.get("impact")), f"free text on consequences, e.g. \"{cut(imp0['impact'], 70)}\""),
          ("`discovery_method`", lambda r: bool(r.get("discovery_method")), "values: " + ", ".join(f"{k} {v}" for k, v in collections.Counter(r.get("discovery_method") for r in ON + WI if r.get("discovery_method")).most_common())),
          ("`exploited_in_wild` is true", lambda r: r.get("exploited_in_wild") is True, "never false, only true or missing"),
          ("`cvss_score`", lambda r: r.get("cvss_score") is not None, "CVSS base score; present only on CVE/GHSA records"),
          ("`affected` non-empty", lambda r: bool(r.get("affected")), f"product or victim named; most frequent WITH-AI value \"{cut(collections.Counter(r['affected'] for r in WI if r['affected']).most_common(1)[0][0], 60)}\""),
          ("`date` at day precision", lambda r: len(r["date"]) == 10, "YYYY-MM-DD; the rest are month-only (YYYY-MM) or year-only"),
          ("record type is threat report", lambda r: r["category"] == "threat-report", "corpus `category` value `threat-report`"),
          ("description of 200+ characters", lambda r: len(r["description"]) >= 200, f"median description {med([len(r['description']) for r in ON])} characters in ON-AI, {med([len(r['description']) for r in WI])} in WITH-AI"),
          ("description is a narrative, not a tracker stub", lambda r: stub_kind(r) == "narrative description", "the three stub kinds of Table 4.4b (OECD pointer, AIID title repeat, AIAAIC facts)"),
          ("`description_provenance` is `original`", lambda r: r.get("description_provenance") == "original",
           f"a value passed through from ingest; {lead(ON)[1]} of the {lead(ON)[2]} ON-AI records start '{lead(ON)[0]}', {'all ' if ofo == len(orig) else ''}{ofo} WITH-AI records start 'AIAAIC-tracked incident' (facts-only stubs, median {med([len(r['description']) for r in orig])} characters, Table 4.4b)"),
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
    drows.append(f"| {dim} | {name} | {what} | `{old}` | `{new}` | {len(o - n)} | {len(n - o)} | {moved} |")
L += ["", "## Where these rules are known to be wrong", "",
      f"**Table 4.7. {len(DEFECTS)} substring defects fixed with word boundaries moved {dmoved} records to another value** ({len(DEFECTS)} fixes)", "",
      "For each fix, the records of the rule's population that the old fragment matched and the new one does not (and vice versa), and the records whose value in that dimension changed; "
      "a fragment match does not always change the value because an earlier rule or another word in the same rule may still fire. Dimension names are the keys of `out/methodology.json`, and every count is recomputed from the patterns on each run.", "",
      "| dimension | rule | what the old substring also matched | old fragment | new fragment | old matched, new does not | new matched, old does not | records whose value changed |", "|---|---|---|---|---|---|---|---|"]
L += drows
rv = load_rv(); J = join_rv(C, rv)["rows"]
ne = [r for r in ON if source_class(r) == "harm-db" and J.get(r["id"], {}).get("gold_labels") == []]
L += ["", f"**Table 4.7b. The {len(ne)} harm-database ON-AI records that the person who hand-labelled could file under no entry** (n = {len(ne)})", "",
      "Fairness evaluations, rights stories and other records carried into ON-AI by the vector list or by step 2's conventional-exploit rule, with the step-2 rule that placed them; "
      "the titles are printed so they can be reviewed before coding. Step 2's own weak spots (WITH-AI rows from CVE/GHSA, malware and jailbreak rows) are in Table 2.5.", "",
      "| id | attack vector | step-2 rule | title |", "|---|---|---|---|"]
L += [f"| {r['id']} | {r['attack_vector']} | {S[r['id']]['rule']} | {cut(r['title'], 100)} |" for r in sorted(ne, key=lambda r: (r["attack_vector"], r["id"]))]

# ---------------------------------------------------------------- appendix: by year
YEARS = range(2022, 2027)
def year_table(num, pop, rows, dim, key, rules):
    out = sum(not YEARS.start <= r["year"] < YEARS.stop for r in rows); by = {y: [r for r in rows if r["year"] == y] for y in YEARS}
    top = lambda sub: (lambda c: f"{c.most_common(1)[0][0]} ({pct(c.most_common(1)[0][1], len(sub))}%)")(collections.Counter(p for r in sub for p in {s.split("-")[0] for s in r["source_ids"]})) if sub else "—"
    L = ["", f"**Table {num}. Appendix: {pop} {dim} by record year (% within year; reflects when each tracker was ingested, Table 1.5)** (n = {len(rows) - out:,})", "",
         f"Columns are record years {YEARS.start}–{YEARS.stop - 1} with the number of {pop} records in each; the {out} {pop} records from other years are left out. "
         "Each column sums to 100 up to rounding, and the first row names the tracker prefix found on most of that year's records, so a column reflects which tracker was ingested, not a trend.", "",
         f"| {dim} | " + " | ".join(f"{y} (n = {len(by[y]):,})" for y in YEARS) + " |", "|---|" + "---|" * len(YEARS),
         "| *most common source prefix* | " + " | ".join(top(by[y]) for y in YEARS) + " |"]
    for v in [n for n, _ in rules] + ["unstated"]:
        L.append(f"| {v} | " + " | ".join(pct(sum(M[r["id"]][key] == v for r in by[y]), len(by[y])) for y in YEARS) + " |")
    return L
L += ["", "## Appendix: do the shares move by record year? Only with the tracker ingested (Table 1.5)"]
L += year_table("4.A1", "ON-AI", ON, "entry point", "entry_point", ENTRY) + year_table("4.A2", "WITH-AI", WI, "AI medium", "ai_role", AIROLE)
write("s04_methodology.md", L)
