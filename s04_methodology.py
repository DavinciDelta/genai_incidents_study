#!/usr/bin/env python3
"""s04_methodology.py — Step 4. Rule-based attack-methodology breakdown of ON-AI and WITH-AI.
Every dimension is a keyword/field rule over title+description+affected. 'unstated' = the record
does not say; those rows are coded from the primary reference in the manual phase.
Output: out/s04_methodology.md
"""
import collections, json, re
from common import load_full, text, table, write, READ, OUT, EXT
S = json.load(open(OUT / "split.json")); C = load_full(); atlas = json.load(open(EXT / "mitre_atlas.json"))["techniques"]
RX = lambda p: re.compile(p, re.I)
def first(rules, t, default="unstated"):
    return next((name for name, rx in rules if rx.search(t)), default)
ENTRY = [("indirect carrier (web/email/doc/tool output)", RX(r"indirect|zero-?click|e-?mail|web ?page|website|document|calendar|retriev|\brag\b|markdown|issue comment|pull request|tool (result|output)|hidden (text|instruction)")),
         ("direct prompt by the user", RX(r"prompt injection|jailbr|system prompt|crafted prompt|user (prompt|input)|chat ?box")),
         ("malicious package / model / skill (supply chain)", RX(r"typosquat|malicious (package|pypi|npm|extension|skill|plugin|model)|backdoored|trojan|supply.chain")),
         ("stolen or leaked credential", RX(r"stolen|leaked (api )?key|credential|access token|valid account|hard-?coded")),
         ("exposed / misconfigured service", RX(r"unauthenticated|exposed|misconfigur|publicly accessible|without auth|default (password|credential)|shodan")),
         ("adversarial input to a classifier", RX(r"adversarial (example|input|patch|perturb)|evad|bypass(ed|ing)? (the )?(detect|filter|classifier)"))]
TARGET = [("agent / copilot / coding assistant / MCP", RX(r"\bagent|copilot|cursor|claude code|gemini cli|codex|mcp|openclaw|cline|windsurf|autogpt|crewai|langgraph|n8n|dify|flowise")),
          ("consumer chatbot / hosted LLM app", RX(r"chatgpt|\bgpt-?[345]|gemini\b|claude\b|bard|chatbot|assistant|character\.ai|grok|deepseek|llama")),
          ("ML/LLM framework or serving library", RX(r"langchain|llama.?index|vllm|ollama|mlflow|tensorflow|pytorch|transformers|comfyui|gradio|triton|sglang|\bray\b|kubeflow")),
          ("RAG / vector / memory store", RX(r"vector (db|database|store)|embedding|pinecone|weaviate|chroma|milvus|qdrant|memory")),
          ("model hub / training pipeline / weights", RX(r"hugging ?face|model hub|weights|checkpoint|fine-?tun|training (data|set|pipeline)|poison")),
          ("detection / classification model", RX(r"detector|classifier|spam|malware detect|facial recognition|fraud detect|content moderation"))]
AIROLE = [("synthetic audio/voice", RX(r"voice ?clon|audio deepfake|synthetic (voice|audio)|robocall|voice (of|imperson)")),
          ("synthetic video", RX(r"deepfake video|video call|synthetic video|face.?swap|live deepfake")),
          ("synthetic image", RX(r"image|photo|nude|undress|explicit|csam|sexual")),
          ("generated text (phishing / lures / disinformation)", RX(r"phish|lure|chat ?bot|generated (text|message|email)|disinformation|propaganda|fake (news|review|article)|influence operation")),
          ("generated or assisted code (malware / tooling)", RX(r"malware|ransomware|exploit (code|generation)|wrote (the )?code|coding|script|payload")),
          ("reconnaissance / planning / orchestration", RX(r"reconnaissance|planning|orchestrat|autonomous|agentic|automated (attack|campaign)|vulnerability research"))]
OBJECTIVE = [("financial fraud / extortion", RX(r"fraud|scam|extort|sextort|ransom|money|payment|transfer|\$\d|million|invest|crypto|bank")),
             ("political / influence", RX(r"election|political|candidate|president|minister|party|vote|propaganda|influence")),
             ("non-consensual / abuse imagery", RX(r"non-?consensual|nude|undress|explicit|csam|sexual|revenge")),
             ("defamation / impersonation of a person", RX(r"impersonat|defam|fake (statement|video of|audio of)|celebrity|ceo|executive")),
             ("intrusion / cyber operation", RX(r"intrusion|breach|hack|credential|network|espionage|apt|threat actor"))]
def dep(r):
    if r.get("cve_ids") or r.get("cwe_ids"): return "software vulnerability (CVE/CWE present)"
    if r["attack_vector"] in ("prompt-injection", "indirect-prompt-injection", "jailbreak", "adversarial-input", "evasion", "model-extraction", "membership-inference", "model-inversion"): return "model behaviour only"
    return "unstated"
def realization(r): return "demonstrated (research/red-team)" if r["category"] in ("research", "research-demonstrated", "red-team") else ("threat report" if r["category"] == "threat-report" else "realized / disclosed")
def order(rules): return "; ".join(name for name, _ in rules)
def year_desc(rows, pop, what):
    return (f"Share of each year's {pop} records by {what}, for 2022–2026. The {sum(not 2022 <= r['year'] <= 2026 for r in rows):,} {pop} records from "
            "other years are left out, so the n column does not sum to the population total. Percentages are within the year (each row) and rounded "
            f"to a whole percent, so a row can sum to 99 or 101. Column names abbreviate the {what} values. Record year is "
            "ingestion-affected (see step 1), so do not read this as a trend.")
def year_table(rows, rules, cols):
    L = ["", "| year | n | " + " | ".join(cols) + " | unstated |", "|---|---|" + "---|" * (len(cols) + 1)]
    for y in range(2022, 2027):
        sub = [r for r in rows if r["year"] == y]; n = len(sub) or 1; c = collections.Counter(first(rules, text(r)) for r in sub)
        L.append(f"| {y} | {len(sub)} | " + " | ".join(f"{100*c[k]/n:.0f}" for k in [x[0] for x in rules] + ["unstated"]) + " |")
    return L
ON = [C[i] for i, s in S.items() if s["population"] == "ON-AI"]; WI = [C[i] for i, s in S.items() if s["population"] == "WITH-AI"]
REAL = ("Read off the corpus `category`: `demonstrated` for research, research-demonstrated and red-team records; `threat report` for "
        "threat-report records; `realized / disclosed` for everything else (real-world incidents and vulnerability disclosures).")
L = ["# Step 4 — Attack-methodology breakdown (rule-based, pre-coding)", "",
     "Generated by `s04_methodology.py` (`make s04`); do not edit by hand. Every dimension is a keyword or field rule over the title + description + "
     "affected text of the ON-AI and WITH-AI records from step 2. The rules of a dimension are tried in a fixed order and the first match wins, so "
     "each record gets exactly one value per dimension. `unstated` means no rule matched: the record does not say, and those rows are coded from "
     "the primary reference in the manual phase. These are rule-based shares to be replaced by hand codes.", "",
     READ + " 95% CI columns are percentile bootstrap intervals over records (2,000 resamples).",
     "", "## ON-AI — the AI system is the target or vector"]
L += table("Entry point", ON, lambda r: first(ENTRY, text(r)), ci=True,
           desc=f"How the adversary first reached the AI system. Rule order: {order(ENTRY)}. A record that mentions two entry points is counted under the earlier rule.")
L += table("Target component", ON, lambda r: first(TARGET, text(r)),
           desc=f"Which part of the AI stack was attacked. Rule order: {order(TARGET)}. A record that names two components is counted under the earlier rule.")
L += table("Did success need a software vulnerability?", ON, dep, ci=True,
           desc="`software vulnerability` if the record has a CVE or CWE id; otherwise `model behaviour only` if its `attack_vector` is a model-level "
                "vector (prompt injection, jailbreak, adversarial input, evasion, model extraction or inversion, membership inference); otherwise `unstated`. This reads corpus "
                "fields, so it describes the stratum; it is not a coded answer.")
L += table("Realization", ON, realization, ci=True, desc=REAL)
L += table("Top ATLAS technique on record (heuristic corpus label)", ON, lambda r: " ".join([(r.get("mitre_atlas") or ["none"])[0], atlas.get((r.get("mitre_atlas") or [""])[0], {}).get("name", "")]), top=8,
           desc="The first MITRE ATLAS technique listed on each record (`mitre_atlas`), or `none` where the record has no ATLAS label. A record can list "
                "further techniques; only the first is counted. These are heuristic corpus labels, shown to describe the stratum only.")
L += ["", "**Entry point by year (% within year)**", "", year_desc(ON, "ON-AI", "entry point")] + year_table(ON, ENTRY, ["indirect", "direct", "supply", "credential", "exposed", "adversarial"])
L += ["", "## WITH-AI — the AI is the attacker's instrument"]
L += table("What the AI produced or did for the attacker", WI, lambda r: first(AIROLE, text(r)), ci=True,
           desc=f"What the AI contributed to the attack. Rule order: {order(AIROLE)}. A record that mentions two roles is counted under the earlier rule.")
L += table("Attacker objective", WI, lambda r: first(OBJECTIVE, text(r)), ci=True,
           desc=f"What the attacker was after. Rule order: {order(OBJECTIVE)}. A record that matches two objectives is counted under the earlier rule.")
L += table("Realization", WI, realization, desc=REAL)
L += ["", "**AI role by year (% within year)**", "", year_desc(WI, "WITH-AI", "AI role")] + year_table(WI, AIROLE, ["voice", "video", "image", "text", "code", "recon"])
cve_with = [r for r in WI if S[r["id"]]["source_class"] == "cve/ghsa"]
L += ["", "## Rule-quality flags", "", "Known weak spots of the rules above, with the number of records each one touches.", "",
      f"- {len(cve_with)} WITH-AI rows come from CVE/GHSA (most common vectors: {', '.join(f'{k} {v}' for k, v in collections.Counter(r['attack_vector'] for r in cve_with).most_common(3))}): likely false positives, review before coding.",
      f"- {sum(r['attack_vector']=='malware' for r in ON)} ON-AI rows carry vector `malware` (AI-ecosystem malicious packages); any describing AI-*written* malware belong in WITH-AI.",
      f"- {sum(r['attack_vector']=='jailbreak' for r in ON)} ON-AI rows are jailbreaks; those whose documented harm is downstream use against a third party belong in BOTH."]
write("s04_methodology.md", L)
