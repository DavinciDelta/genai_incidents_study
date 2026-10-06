# Step 4 — Entry point, target, AI medium and objective, after reclassifying the unstated records

Each ON-AI record gets an entry point (Table 4.1) and a target (4.2), each WITH-AI record an AI medium (4.4) and an attacker objective (4.5), assigned in a fixed order, first hit wins: a text rule (ordered keyword patterns over title + description + affected: the lists ENTRY, TARGET, AIROLE and OBJECTIVE in `s04_methodology.py`), else the corpus attack-vector label where that label maps to exactly one value of the dimension being assigned, else a label-group rule (a group of attack-vector labels fixes the value; for the target, which no label names, the rule at this step is instead a description-prefix test for tracker stubs, placed after the keyword rules so that a system named in the text wins), else a label coded from the text, which may be 'other' or 'no attacker …'; a final 'other' safety net fired 0 times (the script stops if it fires). The corpus-label fallback: malware, supply-chain, backdoor → malicious package / model / skill (supply chain) (entry point); adversarial-input, evasion → adversarial input to a classifier (entry point); indirect-prompt-injection → indirect carrier (web/email/doc/tool output) (entry point); prompt-injection, jailbreak → prompt injection, carrier not stated (entry point); csam-generation → synthetic image (AI medium); deepfake → deepfake, medium not stated (AI medium); csam-generation → non-consensual / abuse imagery (objective). The label-group rules, each group's labels listed once: conventional-exploit (auth-bypass, command-injection, csrf, data-exfiltration, deserialization, dos, info-disclosure, path-traversal, rce, sql-injection, ssrf, xss) → exploit of a conventional software vulnerability (entry point); agent (agent-hijack, memory-poisoning, sandbox-escape, tool-abuse) → via the agent's tools or sandbox (entry point); poisoning (data-poisoning, model-poisoning) → poisoned training data or model (entry point); inference (membership-inference, model-extraction, model-inversion) → query access to the model (extraction / inference) (entry point); conventional-exploit or malicious-package (backdoor, malware, supply-chain) → none: conventional exploit record misplaced in WITH-AI (AI medium); a description starting 'Tracked by the OECD' or 'AI Incident Database (AIID) entry' or 'AIAAIC-tracked incident' → other (tracker stub, no system named) (target). The coded labels live in `coded/relabels.json` (per dimension, id → final, the two coders' labels, an adjudicated flag and a note; `meta.codebook` is the value menu the coders chose from, `meta.agreement` the counts below), made by two independent Claude (claude-fable-5-1) coders per batch, each reading id, title, description (first 700 characters), affected, attack_vector, record_type, channel; a third Claude adjudicator settled every disagreement; no human review yet; coders agreed on 28 of 33 entry points, 191 of 212 targets, 45 of 45 AI media, 498 of 564 objectives, 0 unresolved, and the script checks that the file covers exactly the records the three rules leave unstated and that no final label is 'unstated'. Four values mark records the dimension does not fit and stay visible as rows: 'no attacker: operator harm or model failure (misplaced record)' = harm with no adversary described, so the record belongs in neither population; 'none: conventional exploit record misplaced in WITH-AI' = the attack-vector label is a conventional exploit or a malicious package, so no AI medium is involved and the record is in the wrong population; 'other (tracker stub, no system named)' = a pointer to an external tracker that names no system; 'other' = an attack the coders could not fit to any codebook value; every such record keeps its population and value into step 5 (which reads `objective` from `out/methodology.json`); none is moved or dropped. `out/dataset_pre.csv` holds every ON-AI and WITH-AI record with the values after the first two steps ('unstated' kept) and `out/dataset_post.csv` the pre and post values: the dimension columns are `entry_point`, `target`, `ai_role` (= AI medium) and `objective`, empty when the dimension is not asked of the record's population, in pre as `<dim>` and `<dim>_source` (text rule / corpus label / unstated), in post as `<dim>_pre`, `<dim>_post` and `<dim>_how` plus `coded_note` ('dimension: reason' from the coders, filled only where how is 'coded from text'), and `dependency` holds Table 4.3's value for every record of both populations; both files and `out/methodology.json` are written by `s04_methodology.py` (`make s04`), never by hand; records entered the populations by step 2's rules (Table 2.4), and by channel ON-AI has cve/ghsa 604, harm-db 370, research/other 365 records and WITH-AI cve/ghsa 80, harm-db 1,370, research/other 10 (channel columns are % of that channel, so each 10.0 in WITH-AI's research/other column is one record).

Conventions, 95% CI, pooled rows and the glossary: `out/s01_overview.md` section 0.

**Table 4.0. How each value was assigned** (ON-AI n = 1,339; WITH-AI n = 1,460)

Counts of records per dimension by the step that fixed the value (the four step columns sum to the records); the last column counts records holding one of the four residue values defined above, whichever step set them. In the notes of Tables 4.1–4.5, 'rule' = label-group rule, 'coded' = coded from text, and * marks a value that did not exist before this step.

| dimension (table) | records | text rule | corpus label | label-group rule | coded from text (coders agreed / adjudicated) | value 'other', 'no attacker' or 'none' |
|---|---|---|---|---|---|---|
| ON-AI entry point (4.1) | 1,339 | 686 (51.2%) | 235 (17.6%) | 385 (28.8%) | 33 (2.5%) (28 / 5) | 3 (0.2%) |
| ON-AI target (4.2) | 1,339 | 978 (73.0%) | 0 (0.0%) | 149 (11.1%) | 212 (15.8%) (191 / 21) | 201 (15.0%) |
| WITH-AI AI medium (4.4) | 1,460 | 748 (51.2%) | 607 (41.6%) | 60 (4.1%) | 45 (3.1%) (45 / 0) | 88 (6.0%) |
| WITH-AI objective (4.5) | 1,460 | 893 (61.2%) | 3 (0.2%) | 0 (0.0%) | 564 (38.6%) (498 / 66) | 164 (11.2%) |

**Table 4.1. ON-AI: how did the adversary first reach the AI system? direct prompt by the user 24.7%; 0.2% 'no attacker'** (n = 1,339)

Before reclassification 418 records (31.2%) were unstated; they now hold, largest first: exploit of a conventional software vulnerability* 306 (rule 287, coded 19); via the agent's tools or sandbox* 71 (rule 66, coded 5); poisoned training data or model* 21 (rule); query access to the model (extraction / inference)* 11 (rule); no attacker: operator harm or model failure (misplaced record)* 3 (coded); direct prompt by the user 3 (coded); indirect carrier (web/email/doc/tool output) 1 (coded); exposed / misconfigured service 1 (coded); stolen or leaked credential 1 (coded).

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| direct prompt by the user | 331 | 24.7 | 22.4–27.2 | 15.7 | 32.2 | 32.1 |
| exploit of a conventional software vulnerability | 306 | 22.9 | 20.7–25.1 | 28.0 | 33.0 | 4.1 |
| indirect carrier (web/email/doc/tool output) | 196 | 14.6 | 12.8–16.6 | 18.5 | 3.0 | 20.0 |
| malicious package / model / skill (supply chain) | 131 | 9.8 | 8.2–11.4 | 13.2 | 1.9 | 12.1 |
| prompt injection, carrier not stated | 80 | 6.0 | 4.8–7.2 | 3.0 | 11.4 | 5.5 |
| adversarial input to a classifier | 77 | 5.8 | 4.6–7.0 | 0.3 | 8.9 | 11.5 |
| via the agent's tools or sandbox | 71 | 5.3 | 4.1–6.6 | 6.8 | 1.6 | 6.6 |
| stolen or leaked credential | 63 | 4.7 | 3.7–6.0 | 7.0 | 2.7 | 3.0 |
| exposed / misconfigured service | 49 | 3.7 | 2.7–4.7 | 7.0 | 0.8 | 1.1 |
| poisoned training data or model | 21 | 1.6 | 1.0–2.2 | 0.3 | 3.5 | 1.6 |
| query access to the model (extraction / inference) | 11 | 0.8 | 0.4–1.3 | 0.0 | 0.5 | 2.5 |
| no attacker: operator harm or model failure (misplaced record) | 3 | 0.2 | 0.0–0.5 | 0.2 | 0.5 | 0.0 |

**Table 4.2. ON-AI: which part of the AI stack was attacked? agent / copilot / coding assistant / MCP 48.9%; 15.0% 'other' or 'no attacker'** (n = 1,339)

Before reclassification 361 records (27.0%) were unstated; they now hold, largest first: other (tracker stub, no system named)* 149 (rule); other* 40 (coded); ML/LLM framework or serving library 34 (coded); a model itself (vision, speech or text model attacked directly)* 33 (coded); agent / copilot / coding assistant / MCP 29 (coded); consumer chatbot / hosted LLM app 24 (coded); detection / classification model 15 (coded); model hub / training pipeline / weights 14 (coded); no attacker: operator harm or model failure (misplaced record)* 12 (coded); a non-AI application with an AI feature (web app, CMS plugin, SaaS)* 9 (coded); a physical or embedded AI system (vehicle, robot, device)* 1 (coded); RAG / vector / memory store 1 (coded).

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| agent / copilot / coding assistant / MCP | 655 | 48.9 | 46.2–51.7 | 79.6 | 11.4 | 36.2 |
| consumer chatbot / hosted LLM app | 261 | 19.5 | 17.5–21.7 | 5.5 | 28.4 | 33.7 |
| other (tracker stub, no system named) | 149 | 11.1 | 9.6–12.9 | 0.0 | 40.3 | 0.0 |
| detection / classification model | 60 | 4.5 | 3.4–5.7 | 0.3 | 7.8 | 7.9 |
| model hub / training pipeline / weights | 55 | 4.1 | 3.1–5.2 | 1.0 | 3.2 | 10.1 |
| ML/LLM framework or serving library | 53 | 4.0 | 2.9–5.1 | 7.5 | 0.5 | 1.6 |
| other | 40 | 3.0 | 2.1–3.9 | 4.3 | 0.8 | 3.0 |
| a model itself (vision, speech or text model attacked directly) | 33 | 2.5 | 1.6–3.3 | 0.0 | 4.1 | 4.9 |
| no attacker: operator harm or model failure (misplaced record) | 12 | 0.9 | 0.4–1.4 | 0.0 | 3.2 | 0.0 |
| RAG / vector / memory store | 11 | 0.8 | 0.4–1.3 | 0.8 | 0.0 | 1.6 |
| a non-AI application with an AI feature (web app, CMS plugin, SaaS) | 9 | 0.7 | 0.3–1.2 | 1.0 | 0.3 | 0.5 |
| a physical or embedded AI system (vehicle, robot, device) | 1 | 0.1 | 0.0–0.2 | 0.0 | 0.0 | 0.3 |

**Table 4.3. ON-AI: does the record carry a CVE/CWE (45%), a model-level attack vector (32%) or neither (23%)?** (n = 1,339)

Read off corpus fields, unchanged by the reclassification: a CVE or CWE id, else one of the 8 model-level attack-vector labels (prompt-injection, indirect-prompt-injection, jailbreak, adversarial-input, evasion, model-extraction, membership-inference, model-inversion), else unstated. No channel columns because every CVE/CWE record is cve/ghsa; 147 records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor.

| value | n | % | 95% CI |
|---|---|---|---|
| CVE/CWE present (software vulnerability) | 604 | 45.1 | 42.3–47.8 |
| model-level attack vector, no CVE/CWE | 422 | 31.5 | 29.1–33.9 |
| unstated | 313 | 23.4 | 21.1–25.6 |

**Table 4.4. WITH-AI: what did the AI generate: image, voice, text, video or code? deepfake, medium not stated 41.5%; 6.0% 'other', 'no attacker' or 'none'** (n = 1,460)

Before reclassification 105 records (7.2%) were unstated; they now hold, largest first: none: conventional exploit record misplaced in WITH-AI* 60 (rule); other* 25 (coded); synthetic video 11 (coded); no attacker: operator harm or model failure (misplaced record)* 3 (coded); synthetic audio/voice 3 (coded); deepfake, medium not stated 1 (coded); generated text (phishing / lures / disinformation) 1 (coded); reconnaissance / planning / orchestration 1 (coded).

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| deepfake, medium not stated | 606 | 41.5 | 39.1–43.8 | 46.2 | 41.5 | 10.0 |
| synthetic image | 278 | 19.0 | 17.1–21.1 | 12.5 | 19.4 | 20.0 |
| synthetic audio/voice | 244 | 16.7 | 14.8–18.6 | 0.0 | 17.7 | 20.0 |
| generated text (phishing / lures / disinformation) | 115 | 7.9 | 6.6–9.4 | 37.5 | 5.9 | 40.0 |
| synthetic video | 114 | 7.8 | 6.5–9.2 | 0.0 | 8.3 | 0.0 |
| none: conventional exploit record misplaced in WITH-AI | 60 | 4.1 | 3.1–5.1 | 3.8 | 4.2 | 0.0 |
| other | 25 | 1.7 | 1.1–2.4 | 0.0 | 1.8 | 0.0 |
| generated or assisted code (malware / tooling) | 9 | 0.6 | 0.3–1.1 | 0.0 | 0.6 | 10.0 |
| reconnaissance / planning / orchestration | 6 | 0.4 | 0.1–0.8 | 0.0 | 0.4 | 0.0 |
| no attacker: operator harm or model failure (misplaced record) | 3 | 0.2 | 0.0–0.5 | 0.0 | 0.2 | 0.0 |

**Table 4.5. WITH-AI: what was the attacker after? financial fraud / extortion 32.1%; 11.2% 'other' or 'no attacker'** (n = 1,460)

Before reclassification 564 records (38.6%) were unstated; they now hold, largest first: political / influence 114 (coded); no attacker: operator harm or model failure (misplaced record)* 103 (coded); defamation / impersonation of a person 73 (coded); non-consensual / abuse imagery 63 (coded); intrusion / cyber operation 61 (coded); other* 61 (coded); public deception, not political (hoax, fake news, clickbait)* 58 (coded); harassment or humiliation of a private person* 17 (coded); financial fraud / extortion 14 (coded).

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| financial fraud / extortion | 469 | 32.1 | 29.7–34.5 | 3.8 | 33.6 | 50.0 |
| political / influence | 284 | 19.5 | 17.4–21.6 | 3.8 | 20.4 | 20.0 |
| non-consensual / abuse imagery | 216 | 14.8 | 13.0–16.6 | 6.2 | 15.3 | 10.0 |
| defamation / impersonation of a person | 157 | 10.8 | 9.2–12.4 | 46.2 | 8.8 | 0.0 |
| no attacker: operator harm or model failure (misplaced record) | 103 | 7.1 | 5.8–8.5 | 0.0 | 7.5 | 0.0 |
| intrusion / cyber operation | 95 | 6.5 | 5.3–7.9 | 40.0 | 4.5 | 20.0 |
| other | 61 | 4.2 | 3.2–5.2 | 0.0 | 4.5 | 0.0 |
| public deception, not political (hoax, fake news, clickbait) | 58 | 4.0 | 3.0–4.9 | 0.0 | 4.2 | 0.0 |
| harassment or humiliation of a private person | 17 | 1.2 | 0.7–1.7 | 0.0 | 1.2 | 0.0 |
