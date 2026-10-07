# Step 4 — Entry point, target, AI medium and objective, after reclassifying the unstated records

Each ON-AI record gets an entry point (Table 4.1) and a target (4.2), each WITH-AI record an AI medium (4.4) and an attacker objective (4.5), assigned in a fixed order, first hit wins: a text rule (ordered keyword patterns over title + description + affected: the lists ENTRY, TARGET, AIROLE and OBJECTIVE in `s04_methodology.py`), else the corpus attack-vector label where that label maps to exactly one value of the dimension being assigned, else a label-group rule (a group of attack-vector labels fixes the value; for the target, which no label names, the rule at this step is instead a description-prefix test for tracker stubs, placed after the keyword rules so that a system named in the text wins), else a label coded from the text, which may be 'other' or 'no attacker …'; a final 'other' safety net fired 0 times (the script stops if it fires). The corpus-label fallback: malware, supply-chain, backdoor → malicious package / model / skill (supply chain) (entry point); adversarial-input, evasion → adversarial input to a classifier (entry point); indirect-prompt-injection → indirect carrier (web/email/doc/tool output) (entry point); prompt-injection, jailbreak → prompt injection, carrier not stated (entry point); csam-generation → synthetic image (AI medium); deepfake → deepfake, medium not stated (AI medium); csam-generation → non-consensual / abuse imagery (objective). The label-group rules, each group's labels listed once: conventional-exploit (auth-bypass, command-injection, csrf, data-exfiltration, deserialization, dos, info-disclosure, path-traversal, rce, sql-injection, ssrf, xss) → exploit of a conventional software vulnerability (entry point); agent (agent-hijack, memory-poisoning, sandbox-escape, tool-abuse) → via the agent's tools or sandbox (entry point); poisoning (data-poisoning, model-poisoning) → poisoned training data or model (entry point); inference (membership-inference, model-extraction, model-inversion) → query access to the model (extraction / inference) (entry point); conventional-exploit or malicious-package (backdoor, malware, supply-chain) → none: conventional exploit record misplaced in WITH-AI (AI medium); a description starting 'Tracked by the OECD' or 'AI Incident Database (AIID) entry' or 'AIAAIC-tracked incident' → other (tracker stub, no system named) (target). The coded labels live in `coded/relabels.json` (per dimension, id → final, the two coders' labels, an adjudicated flag and a note; `meta.codebook` is the value menu the coders chose from, `meta.agreement` the counts below), made by two independent Claude (claude-fable-5-1) coders per batch, each reading id, title, description (first 700 characters), affected, attack_vector, record_type, channel; a third Claude adjudicator settled every disagreement; no human review yet; coders agreed on 28 of 33 entry points, 191 of 212 targets, 45 of 45 AI media, 498 of 564 objectives, 0 unresolved, and the script checks that the file covers exactly the records the three rules leave unstated and that no final label is 'unstated'. Four values mark records the dimension does not fit and stay visible as rows: 'no attacker: operator harm or model failure (misplaced record)' = harm with no adversary described, so the record belongs in neither population; 'none: conventional exploit record misplaced in WITH-AI' = the attack-vector label is a conventional exploit or a malicious package, so no AI medium is involved and the record is in the wrong population; 'other (tracker stub, no system named)' = a pointer to an external tracker that names no system; 'other' = an attack the coders could not fit to any codebook value; every such record keeps its population and value into step 5 (which reads `objective` from `out/methodology.json`); none is moved or dropped. `out/dataset_pre.csv` holds every ON-AI and WITH-AI record with the values after the first two steps ('unstated' kept) and `out/dataset_post.csv` the pre and post values: the dimension columns are `entry_point`, `target`, `ai_role` (= AI medium) and `objective`, empty when the dimension is not asked of the record's population, in pre as `<dim>` and `<dim>_source` (text rule / corpus label / unstated), in post as `<dim>_pre`, `<dim>_post` and `<dim>_how` plus `coded_note` ('dimension: reason' from the coders, filled only where how is 'coded from text'), and `dependency` holds Table 4.3's value for every record of both populations; both files and `out/methodology.json` are written by `s04_methodology.py` (`make s04`), never by hand; records entered the populations by step 2's rules (Table 2.4), and by channel ON-AI has cve/ghsa 604, harm-db 370, research/other 365 records and WITH-AI cve/ghsa 80, harm-db 1,370, research/other 10 (channel columns are % of that channel, so each 10.0 in WITH-AI's research/other column is one record).

Conventions, 95% CI, pooled rows and the glossary: `out/s01_overview.md` section 0.

**Table 4.0. How each value was assigned** (ON-AI n = 1,339; WITH-AI n = 1,460)

Counts of records per dimension by the step that fixed the value (the four step columns sum to the records); the last column counts records holding one of the four residue values defined above, whichever step set them. In the notes of Tables 4.1–4.5, 'rule' = label-group rule, 'coded' = coded from text, 'review' = corrected by review, and * marks a value that did not exist before this step.

| dimension (table) | records | text rule | corpus label | label-group rule | coded from text (coders agreed / adjudicated) | corrected by review | value 'other', 'no attacker' or 'none' |
|---|---|---|---|---|---|---|---|
| ON-AI entry point (4.1) | 1,339 | 634 (47.3%) | 207 (15.5%) | 353 (26.4%) | 33 (2.5%) (28 / 5) | 112 (8.4%) | 42 (3.1%) |
| ON-AI target (4.2) | 1,339 | 938 (70.1%) | 0 (0.0%) | 137 (10.2%) | 212 (15.8%) (191 / 21) | 52 (3.9%) | 218 (16.3%) |
| WITH-AI AI medium (4.4) | 1,460 | 721 (49.4%) | 598 (41.0%) | 40 (2.7%) | 45 (3.1%) (45 / 0) | 56 (3.8%) | 95 (6.5%) |
| WITH-AI objective (4.5) | 1,460 | 866 (59.3%) | 1 (0.1%) | 0 (0.0%) | 564 (38.6%) (498 / 66) | 29 (2.0%) | 174 (11.9%) |

**Table 4.0b. Label review: two independent reviewers read 620 rule-assigned labels (36 values); both judged 365 correct (58.9%), 249 were corrected, 6 stayed as assigned with a dissent** (n = 620 labels)

Two independent Claude (claude-fable-5-1) reviewers read each sampled label with the record's title, description (first 700 characters), affected field and corpus labels, and judged it correct or proposed another value from the same codebook; a third reviewer adjudicated every split. A label was corrected when both reviewers rejected it and agreed on the replacement, or when an adjudicator settled a split; 'disputed' = one reviewer rejected it and the adjudicator kept it. Corrections are applied in Tables 4.1–4.5 and `out/dataset_post.csv` (how = 'corrected by review'); the per-value share judged correct is the precision estimate for that rule on a sample of at most 20 records.

| dimension | value | how assigned | records with this label | reviewed | both reviewers: correct | corrected (to) | disputed |
|---|---|---|---|---|---|---|---|
| AI medium | deepfake, medium not stated | corpus label | 605 | 20 | 12 (60.0%) | 8 (synthetic video 4, synthetic image 3, other 1) | 0 |
| AI medium | generated or assisted code (malware / tooling) | text rule | 9 | 9 | 7 (77.8%) | 2 (deepfake, medium not stated 1, generated text (phishing / lures / disinformation) 1) | 0 |
| AI medium | generated text (phishing / lures / disinformation) | text rule | 114 | 20 | 11 (55.0%) | 9 (none: conventional exploit record misplaced in WITH-AI 3, synthetic video 3, deepfake, medium not stated 3) | 0 |
| AI medium | none: conventional exploit record misplaced in WITH-AI | label-group rule | 60 | 20 | 0 (0.0%) | 20 (other 9, no attacker: operator harm or model failure (misplaced record) 6, synthetic video 2, deepfake, medium not stated 2, synthetic image 1) | 0 |
| AI medium | reconnaissance / planning / orchestration | text rule | 5 | 5 | 1 (20.0%) | 4 (other 2, no attacker: operator harm or model failure (misplaced record) 2) | 0 |
| AI medium | synthetic audio/voice | text rule | 241 | 20 | 14 (70.0%) | 6 (synthetic video 6) | 0 |
| AI medium | synthetic image | corpus label | 2 | 2 | 1 (50.0%) | 1 (no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| AI medium | synthetic image | text rule | 276 | 20 | 15 (75.0%) | 5 (no attacker: operator harm or model failure (misplaced record) 2, deepfake, medium not stated 2, none: conventional exploit record misplaced in WITH-AI 1) | 0 |
| AI medium | synthetic video | text rule | 103 | 20 | 19 (95.0%) | 1 (deepfake, medium not stated 1) | 0 |
| entry point | adversarial input to a classifier | corpus label | 56 | 20 | 8 (40.0%) | 12 (no attacker: operator harm or model failure (misplaced record) 9, indirect carrier (web/email/doc/tool output) 1, malicious package / model / skill (supply chain) 1, poisoned training data or model 1) | 0 |
| entry point | adversarial input to a classifier | text rule | 21 | 20 | 16 (80.0%) | 4 (via the agent's tools or sandbox 2, direct prompt by the user 1, poisoned training data or model 1) | 0 |
| entry point | direct prompt by the user | text rule | 328 | 20 | 8 (40.0%) | 12 (exploit of a conventional software vulnerability 4, indirect carrier (web/email/doc/tool output) 3, prompt injection, carrier not stated 3, no attacker: operator harm or model failure (misplaced record) 1, other 1) | 0 |
| entry point | exploit of a conventional software vulnerability | label-group rule | 287 | 20 | 12 (60.0%) | 8 (no attacker: operator harm or model failure (misplaced record) 3, exposed / misconfigured service 2, other 2, prompt injection, carrier not stated 1) | 0 |
| entry point | exposed / misconfigured service | text rule | 48 | 20 | 10 (50.0%) | 10 (exploit of a conventional software vulnerability 8, no attacker: operator harm or model failure (misplaced record) 1, indirect carrier (web/email/doc/tool output) 1) | 0 |
| entry point | indirect carrier (web/email/doc/tool output) | corpus label | 1 | 1 | 1 (100.0%) | 0 | 0 |
| entry point | indirect carrier (web/email/doc/tool output) | text rule | 194 | 20 | 13 (65.0%) | 7 (exploit of a conventional software vulnerability 3, via the agent's tools or sandbox 2, prompt injection, carrier not stated 1, poisoned training data or model 1) | 0 |
| entry point | malicious package / model / skill (supply chain) | corpus label | 98 | 20 | 16 (80.0%) | 3 (poisoned training data or model 2, other 1) | 1 |
| entry point | malicious package / model / skill (supply chain) | text rule | 33 | 20 | 17 (85.0%) | 2 (other 1, poisoned training data or model 1) | 1 |
| entry point | poisoned training data or model | label-group rule | 21 | 20 | 10 (50.0%) | 10 (no attacker: operator harm or model failure (misplaced record) 6, malicious package / model / skill (supply chain) 2, other 1, exploit of a conventional software vulnerability 1) | 0 |
| entry point | prompt injection, carrier not stated | corpus label | 80 | 20 | 7 (35.0%) | 13 (no attacker: operator harm or model failure (misplaced record) 5, indirect carrier (web/email/doc/tool output) 3, exploit of a conventional software vulnerability 3, direct prompt by the user 2) | 0 |
| entry point | query access to the model (extraction / inference) | label-group rule | 11 | 11 | 9 (81.8%) | 2 (other 1, no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| entry point | stolen or leaked credential | text rule | 62 | 20 | 3 (15.0%) | 17 (exploit of a conventional software vulnerability 9, exposed / misconfigured service 2, via the agent's tools or sandbox 2, prompt injection, carrier not stated 1, malicious package / model / skill (supply chain) 1, adversarial input to a classifier 1, other 1) | 0 |
| entry point | via the agent's tools or sandbox | label-group rule | 66 | 20 | 8 (40.0%) | 12 (exploit of a conventional software vulnerability 5, other 4, direct prompt by the user 2, no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| objective | defamation / impersonation of a person | text rule | 84 | 20 | 4 (20.0%) | 15 (intrusion / cyber operation 9, public deception, not political (hoax, fake news, clickbait) 2, non-consensual / abuse imagery 1, financial fraud / extortion 1, no attacker: operator harm or model failure (misplaced record) 1, political / influence 1) | 1 |
| objective | financial fraud / extortion | text rule | 455 | 20 | 20 (100.0%) | 0 | 0 |
| objective | intrusion / cyber operation | text rule | 34 | 20 | 15 (75.0%) | 4 (no attacker: operator harm or model failure (misplaced record) 2, political / influence 2) | 1 |
| objective | non-consensual / abuse imagery | corpus label | 3 | 3 | 1 (33.3%) | 2 (no attacker: operator harm or model failure (misplaced record) 2) | 0 |
| objective | non-consensual / abuse imagery | text rule | 150 | 20 | 14 (70.0%) | 5 (no attacker: operator harm or model failure (misplaced record) 5) | 1 |
| objective | political / influence | text rule | 170 | 20 | 17 (85.0%) | 3 (intrusion / cyber operation 2, defamation / impersonation of a person 1) | 0 |
| target | ML/LLM framework or serving library | text rule | 19 | 19 | 18 (94.7%) | 1 (other 1) | 0 |
| target | RAG / vector / memory store | text rule | 10 | 10 | 8 (80.0%) | 2 (model hub / training pipeline / weights 1, a model itself (vision, speech or text model attacked directly) 1) | 0 |
| target | agent / copilot / coding assistant / MCP | text rule | 626 | 20 | 17 (85.0%) | 3 (a non-AI application with an AI feature (web app, CMS plugin, SaaS) 1, RAG / vector / memory store 1, consumer chatbot / hosted LLM app 1) | 0 |
| target | consumer chatbot / hosted LLM app | text rule | 237 | 20 | 5 (25.0%) | 15 (no attacker: operator harm or model failure (misplaced record) 6, a model itself (vision, speech or text model attacked directly) 4, agent / copilot / coding assistant / MCP 3, ML/LLM framework or serving library 1, model hub / training pipeline / weights 1) | 0 |
| target | detection / classification model | text rule | 45 | 20 | 10 (50.0%) | 9 (other 5, no attacker: operator harm or model failure (misplaced record) 3, model hub / training pipeline / weights 1) | 1 |
| target | model hub / training pipeline / weights | text rule | 41 | 20 | 10 (50.0%) | 10 (no attacker: operator harm or model failure (misplaced record) 3, a model itself (vision, speech or text model attacked directly) 2, other (tracker stub, no system named) 1, ML/LLM framework or serving library 1, RAG / vector / memory store 1, agent / copilot / coding assistant / MCP 1, detection / classification model 1) | 0 |
| target | other (tracker stub, no system named) | label-group rule | 149 | 20 | 8 (40.0%) | 12 (no attacker: operator harm or model failure (misplaced record) 10, consumer chatbot / hosted LLM app 1, agent / copilot / coding assistant / MCP 1) | 0 |

**Table 4.0c. What the review implies for the labels it did not read** (rule-assigned labels per dimension)

The sample took at most 20 records per value, so small values were read in full and large ones were not. 'estimated wrong before review' applies each value's observed error rate to all of its records; 'still wrong after correction' is the same estimate for the records the sample did not reach, i.e. the error that remains in Tables 4.1–4.5 and `out/dataset_post.csv`. Values read in full contribute no remaining error.

| dimension | rule-assigned labels | read in full (values) | reviewed | corrected | estimated wrong before review | still wrong after correction |
|---|---|---|---|---|---|---|
| entry point | 1,306 | 2 of 14 | 252 | 112 | 616 (47.2%) | 504 (38.6%) |
| target | 1,127 | 2 of 7 | 129 | 52 | 405 (35.9%) | 353 (31.3%) |
| AI medium | 1,415 | 3 of 9 | 136 | 56 | 507 (35.8%) | 451 (31.9%) |
| objective | 896 | 1 of 6 | 103 | 29 | 135 (15.0%) | 106 (11.8%) |

**Table 4.1. ON-AI: how did the adversary first reach the AI system? exploit of a conventional software vulnerability 24.7%; 3.1% 'other' or 'no attacker'** (n = 1,339)

Before reclassification 418 records (31.2%) were unstated; they now hold, largest first: exploit of a conventional software vulnerability* 304 (rule 279, coded 19, review 6); via the agent's tools or sandbox* 59 (rule 54, coded 5); no attacker: operator harm or model failure (misplaced record)* 14 (review 11, coded 3); poisoned training data or model* 11 (rule); query access to the model (extraction / inference)* 9 (rule); other* 8 (review); direct prompt by the user 5 (coded 3, review 2); exposed / misconfigured service 3 (review 2, coded 1); malicious package / model / skill (supply chain) 2 (review); prompt injection, carrier not stated 1 (review); indirect carrier (web/email/doc/tool output) 1 (coded); stolen or leaked credential 1 (coded). Audit (Table 4.0b): fewer than half of the sampled rule-assigned labels were correct for stolen or leaked credential (3 of 20), prompt injection, carrier not stated (7 of 20), direct prompt by the user (8 of 20), via the agent's tools or sandbox (8 of 20); the unreviewed records under these values carry that error rate.

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| exploit of a conventional software vulnerability | 331 | 24.7 | 22.3–27.0 | 32.9 | 31.6 | 4.1 |
| direct prompt by the user | 324 | 24.2 | 22.0–26.7 | 14.9 | 31.9 | 31.8 |
| indirect carrier (web/email/doc/tool output) | 197 | 14.7 | 12.8–16.7 | 17.9 | 3.5 | 20.8 |
| malicious package / model / skill (supply chain) | 130 | 9.7 | 8.1–11.3 | 13.4 | 1.9 | 11.5 |
| prompt injection, carrier not stated | 73 | 5.5 | 4.3–6.7 | 2.6 | 10.0 | 5.5 |
| via the agent's tools or sandbox | 65 | 4.9 | 3.8–6.0 | 7.0 | 1.4 | 4.9 |
| adversarial input to a classifier | 62 | 4.6 | 3.6–5.8 | 0.0 | 6.5 | 10.4 |
| stolen or leaked credential | 46 | 3.4 | 2.5–4.5 | 5.1 | 1.9 | 2.2 |
| exposed / misconfigured service | 43 | 3.2 | 2.2–4.2 | 6.0 | 0.8 | 1.1 |
| no attacker: operator harm or model failure (misplaced record) | 30 | 2.2 | 1.5–3.1 | 0.2 | 7.3 | 0.5 |
| poisoned training data or model | 17 | 1.3 | 0.7–1.9 | 0.0 | 1.6 | 3.0 |
| other | 12 | 0.9 | 0.4–1.4 | 0.0 | 1.4 | 1.9 |
| query access to the model (extraction / inference) | 9 | 0.7 | 0.3–1.1 | 0.0 | 0.3 | 2.2 |

**Table 4.2. ON-AI: which part of the AI stack was attacked? agent / copilot / coding assistant / MCP 49.1%; 16.3% 'other' or 'no attacker'** (n = 1,339)

Before reclassification 361 records (27.0%) were unstated; they now hold, largest first: other (tracker stub, no system named)* 137 (rule); other* 40 (coded); ML/LLM framework or serving library 34 (coded); a model itself (vision, speech or text model attacked directly)* 33 (coded); agent / copilot / coding assistant / MCP 30 (coded 29, review 1); consumer chatbot / hosted LLM app 25 (coded 24, review 1); no attacker: operator harm or model failure (misplaced record)* 22 (coded 12, review 10); detection / classification model 15 (coded); model hub / training pipeline / weights 14 (coded); a non-AI application with an AI feature (web app, CMS plugin, SaaS)* 9 (coded); a physical or embedded AI system (vehicle, robot, device)* 1 (coded); RAG / vector / memory store 1 (coded). Audit (Table 4.0b): fewer than half of the sampled rule-assigned labels were correct for consumer chatbot / hosted LLM app (5 of 20), other (tracker stub, no system named) (8 of 20); the unreviewed records under these values carry that error rate.

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| agent / copilot / coding assistant / MCP | 657 | 49.1 | 46.4–51.8 | 79.5 | 11.6 | 36.7 |
| consumer chatbot / hosted LLM app | 248 | 18.5 | 16.4–20.7 | 5.3 | 26.8 | 32.1 |
| other (tracker stub, no system named) | 138 | 10.3 | 8.8–11.9 | 0.0 | 37.3 | 0.0 |
| ML/LLM framework or serving library | 54 | 4.0 | 3.1–5.2 | 7.8 | 0.5 | 1.4 |
| detection / classification model | 52 | 3.9 | 2.9–4.9 | 0.3 | 5.9 | 7.7 |
| model hub / training pipeline / weights | 48 | 3.6 | 2.7–4.6 | 0.5 | 2.2 | 10.1 |
| other | 46 | 3.4 | 2.5–4.4 | 4.3 | 1.9 | 3.6 |
| a model itself (vision, speech or text model attacked directly) | 40 | 3.0 | 2.1–3.9 | 0.0 | 4.6 | 6.3 |
| no attacker: operator harm or model failure (misplaced record) | 34 | 2.5 | 1.7–3.5 | 0.0 | 8.9 | 0.3 |
| RAG / vector / memory store | 11 | 0.8 | 0.4–1.3 | 1.2 | 0.0 | 1.1 |
| a non-AI application with an AI feature (web app, CMS plugin, SaaS) | 10 | 0.7 | 0.3–1.3 | 1.2 | 0.3 | 0.5 |
| a physical or embedded AI system (vehicle, robot, device) | 1 | 0.1 | 0.0–0.2 | 0.0 | 0.0 | 0.3 |

**Table 4.3. ON-AI: does the record carry a CVE/CWE (45%), a model-level attack vector (32%) or neither (23%)?** (n = 1,339)

Read off corpus fields, unchanged by the reclassification: a CVE or CWE id, else one of the 8 model-level attack-vector labels (prompt-injection, indirect-prompt-injection, jailbreak, adversarial-input, evasion, model-extraction, membership-inference, model-inversion), else unstated. No channel columns because every CVE/CWE record is cve/ghsa; 147 records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor.

| value | n | % | 95% CI |
|---|---|---|---|
| CVE/CWE present (software vulnerability) | 604 | 45.1 | 42.3–47.8 |
| model-level attack vector, no CVE/CWE | 422 | 31.5 | 29.1–33.9 |
| unstated | 313 | 23.4 | 21.1–25.6 |

**Table 4.4. WITH-AI: what did the AI generate: image, voice, text, video or code? deepfake, medium not stated 41.6%; 6.5% 'other', 'no attacker' or 'none'** (n = 1,460)

Before reclassification 105 records (7.2%) were unstated; they now hold, largest first: none: conventional exploit record misplaced in WITH-AI* 40 (rule); other* 34 (coded 25, review 9); synthetic video 13 (coded 11, review 2); no attacker: operator harm or model failure (misplaced record)* 9 (review 6, coded 3); deepfake, medium not stated 3 (review 2, coded 1); synthetic audio/voice 3 (coded); generated text (phishing / lures / disinformation) 1 (coded); reconnaissance / planning / orchestration 1 (coded); synthetic image 1 (review). Audit (Table 4.0b): fewer than half of the sampled rule-assigned labels were correct for none: conventional exploit record misplaced in WITH-AI (0 of 20), reconnaissance / planning / orchestration (1 of 5); the unreviewed records under these values carry that error rate.

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| deepfake, medium not stated | 607 | 41.6 | 39.2–44.0 | 46.2 | 41.5 | 10.0 |
| synthetic image | 276 | 18.9 | 16.9–21.0 | 11.2 | 19.3 | 20.0 |
| synthetic audio/voice | 238 | 16.3 | 14.5–18.2 | 0.0 | 17.2 | 20.0 |
| synthetic video | 128 | 8.8 | 7.3–10.2 | 0.0 | 9.3 | 10.0 |
| generated text (phishing / lures / disinformation) | 107 | 7.3 | 6.1–8.7 | 33.8 | 5.6 | 30.0 |
| none: conventional exploit record misplaced in WITH-AI | 44 | 3.0 | 2.1–4.0 | 8.8 | 2.7 | 0.0 |
| other | 37 | 2.5 | 1.8–3.4 | 0.0 | 2.7 | 0.0 |
| no attacker: operator harm or model failure (misplaced record) | 14 | 1.0 | 0.5–1.5 | 0.0 | 1.0 | 0.0 |
| generated or assisted code (malware / tooling) | 7 | 0.5 | 0.2–0.9 | 0.0 | 0.4 | 10.0 |
| reconnaissance / planning / orchestration | 2 | 0.1 | 0.0–0.3 | 0.0 | 0.1 | 0.0 |

**Table 4.5. WITH-AI: what was the attacker after? financial fraud / extortion 32.2%; 11.9% 'other' or 'no attacker'** (n = 1,460)

Before reclassification 564 records (38.6%) were unstated; they now hold, largest first: political / influence 114 (coded); no attacker: operator harm or model failure (misplaced record)* 103 (coded); defamation / impersonation of a person 73 (coded); non-consensual / abuse imagery 63 (coded); intrusion / cyber operation 61 (coded); other* 61 (coded); public deception, not political (hoax, fake news, clickbait)* 58 (coded); harassment or humiliation of a private person* 17 (coded); financial fraud / extortion 14 (coded). Audit (Table 4.0b): fewer than half of the sampled rule-assigned labels were correct for defamation / impersonation of a person (5 of 20); the unreviewed records under these values carry that error rate.

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| financial fraud / extortion | 470 | 32.2 | 29.9–34.5 | 3.8 | 33.7 | 50.0 |
| political / influence | 284 | 19.5 | 17.3–21.6 | 1.2 | 20.5 | 20.0 |
| non-consensual / abuse imagery | 210 | 14.4 | 12.7–16.2 | 6.2 | 14.9 | 10.0 |
| defamation / impersonation of a person | 143 | 9.8 | 8.4–11.4 | 36.2 | 8.3 | 0.0 |
| no attacker: operator harm or model failure (misplaced record) | 113 | 7.7 | 6.4–9.2 | 0.0 | 8.2 | 0.0 |
| intrusion / cyber operation | 102 | 7.0 | 5.8–8.4 | 52.5 | 4.2 | 20.0 |
| other | 61 | 4.2 | 3.2–5.2 | 0.0 | 4.5 | 0.0 |
| public deception, not political (hoax, fake news, clickbait) | 60 | 4.1 | 3.1–5.1 | 0.0 | 4.4 | 0.0 |
| harassment or humiliation of a private person | 17 | 1.2 | 0.7–1.7 | 0.0 | 1.2 | 0.0 |
