# Step 1 — Overview (genai-incidents 2.12.0, full JSON sha256 83295199da35…)

## A. README usage snippet (package API)

```
INC-01288 - LAAF v2.0 — Empirical LPCI breakthrough rates of 67–100% across 5 production LLMs
INC-00924 - EchoLeak — zero-click Microsoft Copilot data exfiltration via email prompt injection
INC-00834 - Clinejection — CI/CD pipeline compromise via Cline's issue triage bot, 4,000 machines infected
INC-01297 - Langflow CSV Agent RCE via Prompt Injection (CVE-2026-27966)
INC-13450 - The shell tool command allowlist in the SecurityPolicy of OpenHuman desktop agent through 0.54.0 (default Supervised security policy) can be bypassed to execute arbitrary OS com...
INC-13451 - Read-only transaction bypass in the pgAdmin 4 AI Assistant allows an attacker who can influence database content that the assistant reads to execute arbitrary SQL with the privi...
INC-13832 - npm PraisonAI AgentOS exposes unauthenticated agent listing and invocation
INC-08351 - PraisonAI vulnerable to sandbox escape via `print.__self__` builtins module leak in `execute_code` (subprocess mode)
INC-00816 - Claude Code — Prompt Injection (CVE-2026-39861)
INC-08751 - Gemini CLI: Remote Code Execution via workspace trust and tool allowlisting bypasses
INC-08998 - PraisonAI: Python Sandbox Escape via str Subclass startswith() Override in execute_code
INC-01515 - nanobot — Prompt Injection (CVE-2026-33654)
INC-01192 - In its design for automatic terminal command execution, AI Code offers two options: Execute safe commands and execute all commands.
INC-14611 - In its design for automatic terminal command execution, SakaDev offers two options: Execute safe commands and execute all commands.
INC-01193 - In its design for automatic terminal command execution, HAI Build Code Generator offers two options: Execute safe commands and Execute all commands.
INC-01194 - In its design for automatic terminal command execution, Sixth offers two options: Execute safe commands and Execute all commands.
INC-00868 - Cursor — Prompt Injection (CVE-2026-22708)
INC-09491 - CAI find_file Agent Tool has Command Injection Vulnerability Through Argument Injection
INC-00334 - AI-Enabled Cyberattacks Surge, Slashing Breakout Times to Under 30 Minutes
INC-14738 - Critical AI System Vulnerabilities in OpenClaw and Langflow Lead to Security Risks and Exploitation
INC-00863 - Critical Remote Code Execution Vulnerability in Google's Antigravity AI IDE Patched
INC-00282 - AI-Driven Cyberattacks Exploit Zero-Day Vulnerabilities, Escalating Security Risks
INC-14504 - Shared API Keys Lead to Security Incidents Among Enterprise AI Agents
INC-14571 - Critical Vulnerability in Cursor AI Code Editor Enables Automatic Code Execution
INC-15894 - pgAdmin 4: AI Assistant read-only transaction bypass via sqlparse/PostgreSQL lexer disagreement (incomplete fix for CVE-2026-12045)
INC-16084 - Agno up to and including 2.5.8 is vulnerable to Remote Code Execution (RCE) via prompt injection.
INC-16324 - Langroid: Neo4jChatAgent executes LLM-generated Cypher without validation (prompt-to-Cypher injection; config-conditional RCE), mirroring the SQLChatAgent bug fixed in CVE-2026-...
INC-16469 - PraisonAI before 1.6.78 Remote Code Execution via CodeAgent
INC-16487 - DBHub HTTP transport DNS rebinding allows unauthenticated browser-origin SQL execution
INC-16619 - FrontMCP: CodeCall sandbox escape -> host RCE via live Zod schema exposure by getTool
INC-16666 - Flowise: CSV Agent Prompt Injection Remote Code Execution Vulnerability
INC-16738 - PapersGPT for Zotero 0.6.1 RCE via Unsanitized LLM Response eval()
INC-16754 - Flowise before 3.1.3 Prompt Injection RCE via CSV Agent
INC-16837 - Open GenAI Stack (aka ogx-ai) 2026-06-11, as used in the Meta AI backend for WhatsApp and other products, allows code execution because prompt injection (with Jinja2 template sy...
INC-17037 - LaVague 0.2.35 Remote Code Execution via eval extraction
by_cve("CVE-2026-21520") -> ['INC-01434']
resolve_id("INC-00139") -> INC-00139
```

## B. What the data is

- Records: **15,666**; landmark tier: **1,915**; years 1983–2026
- Records with a CVE: 7,475; with a CWE: 7,801; merged from >1 source: 1,340
- Median description length: 281 chars

**Source (prefix of source_ids; a record may carry several)** (n = 18,765)

| value | n | % |
|---|---|---|
| CVE | 9,136 | 48.7 |
| OECD | 4,160 | 22.2 |
| AIID | 1,552 | 8.3 |
| GHSA | 1,018 | 5.4 |
| AVID | 321 | 1.7 |
| PROMPTFOO | 174 | 0.9 |
| ARXIV | 171 | 0.9 |
| RES | 133 | 0.7 |
| INC | 113 | 0.6 |
| LEGACY | 108 | 0.6 |

**Disclosure channel (derived)** (n = 15,666)

| value | n | % |
|---|---|---|
| cve/ghsa | 8,063 | 51.5 |
| harm-db | 7,112 | 45.4 |
| research/other | 491 | 3.1 |

**Category** (n = 15,666)

| value | n | % |
|---|---|---|
| vulnerability-disclosure | 8,034 | 51.3 |
| real-world | 7,161 | 45.7 |
| research | 307 | 2.0 |
| threat-report | 111 | 0.7 |
| research-demonstrated | 41 | 0.3 |
| red-team | 12 | 0.1 |

**Tier** (n = 15,666)

| value | n | % |
|---|---|---|
| feed | 13,751 | 87.8 |
| landmark | 1,915 | 12.2 |

**Quality tier** (n = 15,666)

| value | n | % |
|---|---|---|
| reviewed | 11,131 | 71.1 |
| auto | 4,416 | 28.2 |
| curated | 119 | 0.8 |

**Corpus** (n = 15,666)

| value | n | % |
|---|---|---|
| security | 15,121 | 96.5 |
| ai-harm | 545 | 3.5 |

**Record year (2019+)** (n = 15,213) — record year is ingestion-affected

| value | n | % |
|---|---|---|
| 2026 | 7,401 | 48.6 |
| 2025 | 2,108 | 13.9 |
| 2024 | 1,671 | 11.0 |
| 2022 | 1,076 | 7.1 |
| 2023 | 991 | 6.5 |
| 2020 | 985 | 6.5 |
| 2021 | 865 | 5.7 |
| 2019 | 116 | 0.8 |

## B2. General breakdowns


**attack_vector** (n = 15,666)

| value | n | % |
|---|---|---|
| other | 4,314 | 27.5 |
| rce | 2,306 | 14.7 |
| xss | 1,336 | 8.5 |
| auth-bypass | 1,213 | 7.7 |
| deepfake | 1,182 | 7.5 |
| dos | 693 | 4.4 |
| path-traversal | 675 | 4.3 |
| ssrf | 557 | 3.6 |
| data-exfiltration | 454 | 2.9 |
| misinformation | 383 | 2.4 |
| prompt-injection | 347 | 2.2 |
| info-disclosure | 342 | 2.2 |
| command-injection | 325 | 2.1 |
| privacy-violation | 324 | 2.1 |
| deserialization | 266 | 1.7 |

**severity** (n = 15,666)

| value | n | % |
|---|---|---|
| Medium | 6,478 | 41.4 |
| High | 5,996 | 38.3 |
| Critical | 2,716 | 17.3 |
| Low | 476 | 3.0 |

**OWASP LLM Top 10 (2026) codes — a record may carry several** (n = 21,065)

| value | n | % |
|---|---|---|
| LLM04 | 8,318 | 39.5 |
| LLM10 | 6,854 | 32.5 |
| LLM07 | 2,498 | 11.9 |
| LLM02 | 1,074 | 5.1 |
| LLM03 | 783 | 3.7 |
| LLM08 | 730 | 3.5 |
| LLM01 | 546 | 2.6 |
| LLM05 | 194 | 0.9 |
| LLM06 | 44 | 0.2 |
| LLM09 | 24 | 0.1 |

**OWASP Agentic (ASI) codes** (n = 21,706)

| value | n | % |
|---|---|---|
| ASI04 | 8,133 | 37.5 |
| ASI05 | 5,843 | 26.9 |
| ASI09 | 2,725 | 12.6 |
| ASI03 | 2,409 | 11.1 |
| ASI08 | 783 | 3.6 |
| ASI02 | 730 | 3.4 |
| ASI10 | 459 | 2.1 |
| ASI01 | 458 | 2.1 |
| ASI06 | 139 | 0.6 |
| ASI07 | 27 | 0.1 |

**CWE (top)** (n = 10,583)

| value | n | % |
|---|---|---|
| CWE-79 | 1,341 | 12.7 |
| CWE-22 | 609 | 5.8 |
| CWE-918 | 540 | 5.1 |
| CWE-863 | 368 | 3.5 |
| CWE-94 | 363 | 3.4 |
| CWE-862 | 356 | 3.4 |
| CWE-78 | 305 | 2.9 |
| CWE-20 | 244 | 2.3 |
| CWE-200 | 235 | 2.2 |
| CWE-502 | 225 | 2.1 |

> Labels above are the corpus's own heuristic assignments (see its DATASHEET). They describe what the
> heuristics matched, not measured prevalence.

## C. What incident-rank-validation shows about this data

- Snapshot: 7,714 records (May 2026); **6,207** resolve to a current record, 240 do not.
- Label source: stage-1 rules 548, stage-2 LLM 5,659.
- Gold set: 1,200 hand-adjudicated rows; adjudicator overrode the model on 553; out of scope (no entry applies): 444.
- Headline: weighted κ vote-vs-data = 0.203; frame-blind entries: LLM04, LLM08, LLM10.

**Vote rank vs data rank vs share of records, per entry** (sorted by vote rank)

| Entry | Name | Vote rank | Data rank (90% CI) | % of classifier labels | % of gold labels | Recall | Precision | n gold |
|---|---|---|---|---|---|---|---|---|
| LLM01 | Prompt Injection | 1 | 12 (4–18) | 4.0 | 5.9 | 0.33 | 0.93 | 145 |
| LLM02 | Sensitive Information Disclosure | 2 | 2 (1–6) | 17.8 | 8.4 | 0.34 | 0.69 | 147 |
| LLM06 | Excessive Agency | 4 | 7 (2–14) | 6.4 | 8.6 | 0.38 | 0.62 | 154 |
| NEW-PMP | Persistent Memory Poisoning | 4 | 16 (6–20) | 0.1 | 0.7 | 0.07 | 0.94 | 106 |
| LLM03 | Supply Chain Vulnerabilities | 5 | 9 (3–16) | 7.4 | 11.7 | 0.36 | 0.93 | 169 |
| LLM04 | Data and Model Poisoning | 6 | 4 (1–9) | 2.9 | 6.2 | 0.29 | 0.71 | 141 |
| NEW-MTIE | MCP Tool Interface Exploitation | 7 | 16 (6–20) | 0.5 | 3.7 | 0.20 | 0.54 | 125 |
| LLM10 | Unbounded Consumption | 8 | 15 (5–19) | 1.1 | 4.0 | 0.30 | 0.88 | 146 |
| ROLL-CMSB | Cross-Modal Safety Bypass | 10 | 9 (3–16) | 2.1 | 2.9 | 0.17 | 0.44 | 119 |
| LLM08 | Vector and Embedding Weaknesses | 11 | 12 (4–19) | 0.1 | 0.3 | 0.02 | 0.13 | 101 |
| NEW-MA | Model Misalignment | 11 | 10 (3–16) | 2.1 | 6.5 | 0.30 | 0.73 | 139 |
| LLM07 | Hidden Context Exposure | 11.5 | 6 (2–13) | 0.6 | 0.7 | 0.06 | 0.31 | 106 |
| LLM05 | Improper Output Handling | 13 | 10 (3–16) | 9.4 | 10.2 | 0.35 | 0.76 | 161 |
| LLM09 | Misinformation | 13 | 2 (1–5) | 30.6 | 16.8 | 0.39 | 0.85 | 157 |
| ROLL-LAPTF | LLM Artifact Promotion Trust Failure | 15 | 16 (6–20) | 0.0 | 0.1 | 0.02 | 0.75 | 101 |
| ROLL-SICG | Systemic Insecure Code Generation | 16 | 16 (6–20) | 0.3 | 2.1 | 0.15 | 0.59 | 116 |
| NEW-WLA | Weaponized LLM Abuse | 17 | 8 (3–15) | 14.2 | 9.7 | 0.49 | 0.72 | 155 |
| ROLL-CFAS | Compositional Fine-tuning Alignment Subversion | 18 | 14 (4–20) | 0.0 | 0.1 | 0.01 | 0.33 | 100 |
| NEW-ITSCD | Inference-Time Side-Channel Disclosure | 19 | 17 (6–20) | 0.0 | 0.3 | 0.04 | 0.75 | 103 |
| NEW-MSDA | Model Scheming and Deceptive Alignment | 19 | 16 (6–20) | 0.2 | 1.0 | 0.08 | 0.82 | 108 |

**Where the gold-set out-of-scope rows come from**


**source class of out-of-scope rows** (n = 441)

| value | n | % |
|---|---|---|
| harm-db | 405 | 91.8 |
| cve/ghsa | 25 | 5.7 |
| research/other | 11 | 2.5 |

**attack_vector of out-of-scope rows** (n = 441)

| value | n | % |
|---|---|---|
| other | 194 | 44.0 |
| rce | 93 | 21.1 |
| deepfake | 61 | 13.8 |
| privacy-violation | 18 | 4.1 |
| algorithmic-bias | 15 | 3.4 |
| data-exfiltration | 13 | 2.9 |
