#!/usr/bin/env python3
"""s02_split.py — Step 2. Dissect the corpus into ON-AI vs WITH-AI.

Deciding question: whose asset is the AI system?
  ON-AI   — the AI system belongs to the victim and the adversary subverts it (it is the target or vector).
  WITH-AI — the AI is the adversary's instrument against a conventional target.
  BOTH    — both signals present (e.g. a jailbreak whose output is then used against a third party).
  UNRESOLVED — adversary vocabulary present, no population signal; hand review.
  NONE    — no adversary (disclosure without exploitation, operator harm, model failure).
Rules are deterministic over attack_vector, CVE/CWE presence, category and title+description text.
Output: out/split.json (id → population, rule, …) and out/s02_split.md (tables + gold-set cross-check).
"""
import collections, json, re
from common import load_full, load_rv, join_rv, source_class, text, boot_ci, table, write

ON_VEC = {"prompt-injection", "indirect-prompt-injection", "jailbreak", "tool-abuse", "agent-hijack", "memory-poisoning",
          "model-poisoning", "backdoor", "adversarial-input", "evasion", "model-extraction", "model-inversion", "membership-inference", "sandbox-escape"}
WITH_VEC = {"deepfake", "phishing", "csam-generation"}
CODE_VEC = {"rce", "ssrf", "sql-injection", "command-injection", "path-traversal", "deserialization", "xss", "auth-bypass",
            "info-disclosure", "dos", "csrf", "data-exfiltration", "supply-chain", "malware"}
ADV = re.compile(r"attacker|threat actor|hacker|adversar|campaign|exploited|abused|scam|fraud|extort|stole|breach|malicious|\bAPT\b|state-sponsored|cybercrim|ransomware|phish|impersonat|weaponi[sz]", re.I)
WITH_KW = re.compile(r"deepfake|voice ?clon|synthetic (media|audio|video|image)|ai-generated (image|video|audio|voice|content|phish|malware)|used (chatgpt|claude|gemini|an? (llm|ai|chatbot|model)) to|ai-(assisted|enabled|powered|driven) (attack|phish|scam|fraud|malware|hack|cyber)|influence operation|disinformation campaign|llm-(assisted|generated|written) malware|wormgpt|fraudgpt", re.I)
ON_KW = re.compile(r"prompt injection|jailbr|system prompt|guardrail|exfiltrat\w+ (via|through) (the )?(model|agent|copilot|assistant|chatbot)|tool (call|invocation)|mcp server|agent (hijack|abuse)|model (theft|extraction|poison)|training data poison|rag poison|memory poison", re.I)

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

F = [C[i] for i, s in S.items() if s["population"] in ("ON-AI", "WITH-AI", "BOTH")]
L = ["# Step 2 — ON-AI vs WITH-AI split", ""]
L += table("Population (all records)", list(S.values()), lambda s: s["population"])
L += table("Population within the adversary frame", F, lambda r: S[r["id"]]["population"], ci=True)
L += table("Rule that fired (adversary frame)", F, lambda r: S[r["id"]]["rule"])
L += ["", "**Population × disclosure channel** (adversary frame; this is Figure 1 Panel B)", "", "| channel | n | ON-AI | WITH-AI | BOTH |", "|---|---|---|---|---|"]
for ch in ("cve/ghsa", "harm-db", "research/other"):
    sub = [r for r in F if S[r["id"]]["source_class"] == ch]; c = collections.Counter(S[r["id"]]["population"] for r in sub)
    L.append(f"| {ch} | {len(sub)} | {c['ON-AI']} ({100*c['ON-AI']/len(sub):.0f}%) | {c['WITH-AI']} ({100*c['WITH-AI']/len(sub):.0f}%) | {c['BOTH']} |")
L += ["", "**Population × record year** (adversary frame)", "", "| year | ON-AI | WITH-AI | BOTH |", "|---|---|---|---|"]
for y in range(2020, 2027):
    c = collections.Counter(S[r["id"]]["population"] for r in F if r["year"] == y); L.append(f"| {y} | {c['ON-AI']} | {c['WITH-AI']} | {c['BOTH']} |")
for pop in ("ON-AI", "WITH-AI"):
    sub = [r for r in F if S[r["id"]]["population"] == pop]
    L += table(f"{pop}: attack_vector", sub, lambda r: r.get("attack_vector") or "other", top=8)
    L += table(f"{pop}: category", sub, lambda r: r["category"])
U = [C[i] for i, s in S.items() if s["population"] == "UNRESOLVED"]
L += table("UNRESOLVED: which adversary word fired", [m.group(0).lower() for r in U for m in ADV.finditer(text(r))], lambda w: w, top=8)

# ---- independent check: incident-rank-validation gold labels by population
rv = load_rv(); J = join_rv(C, rv)["rows"]
L += ["", "## Cross-check against incident-rank-validation human-adjudicated labels", "",
      "| population | gold rows | out of scope | top adjudicated entries |", "|---|---|---|---|"]
for pop in ("ON-AI", "WITH-AI", "BOTH", "UNRESOLVED", "NONE"):
    g = [J[i] for i in J if S[i]["population"] == pop and J[i]["gold_labels"] is not None]
    oos = sum(1 for x in g if x["gold_labels"] == []); c = collections.Counter(e for x in g for e in x["gold_labels"])
    L.append(f"| {pop} | {len(g)} | {oos} ({100*oos/max(len(g),1):.0f}%) | {', '.join(f'{e} {n}' for e, n in c.most_common(5))} |")
adv_ids = [i for i, s in S.items() if s["population"] in ("ON-AI", "WITH-AI", "BOTH")]
L += ["", f"Adversary frame: {len(adv_ids):,} rows; {sum(i in J for i in adv_ids):,} carry a rank-validation classifier label; {sum(i in J and J[i]['gold_labels'] is not None for i in adv_ids):,} carry a human-adjudicated label."]
write("s02_split.md", L)
