# Step 4 — Entry point, target, AI medium and objective, after reclassifying the unstated records

Each ON-AI record gets an entry point (Table 4.1) and a target (4.2), each WITH-AI record an AI medium (4.4) and an attacker objective (4.5), assigned in a fixed order, first hit wins: a text rule (ordered keyword patterns over title + description + affected: the lists ENTRY, TARGET, AIROLE and OBJECTIVE in `s04_methodology.py`), else the corpus attack-vector label where that label maps to exactly one value of the dimension being assigned, else a label-group rule (a group of attack-vector labels fixes the value; for the target, which no label names, the rule at this step is instead a description-prefix test for tracker stubs, placed after the keyword rules so that a system named in the text wins), else a label coded from the text, which may be 'other' or 'no attacker …'; a final 'other' safety net fired 0 times (the script stops if it fires). The corpus-label fallback: malware, supply-chain, backdoor → malicious package / model / skill (supply chain) (entry point); adversarial-input, evasion → adversarial input to a classifier (entry point); indirect-prompt-injection → indirect carrier (web/email/doc/tool output) (entry point); prompt-injection, jailbreak → prompt injection, carrier not stated (entry point); csam-generation → synthetic image (AI medium); deepfake → deepfake, medium not stated (AI medium); csam-generation → non-consensual / abuse imagery (objective). The label-group rules, each group's labels listed once: conventional-exploit (auth-bypass, command-injection, csrf, data-exfiltration, deserialization, dos, info-disclosure, path-traversal, rce, sql-injection, ssrf, xss) → exploit of a conventional software vulnerability (entry point); agent (agent-hijack, memory-poisoning, sandbox-escape, tool-abuse) → via the agent's tools or sandbox (entry point); poisoning (data-poisoning, model-poisoning) → poisoned training data or model (entry point); inference (membership-inference, model-extraction, model-inversion) → query access to the model (extraction / inference) (entry point); conventional-exploit or malicious-package (backdoor, malware, supply-chain) → none: conventional exploit record misplaced in WITH-AI (AI medium); a description starting 'Tracked by the OECD' or 'AI Incident Database (AIID) entry' or 'AIAAIC-tracked incident' → other (tracker stub, no system named) (target). The coded labels live in `coded/relabels.json` (per dimension, id → final, the two coders' labels, an adjudicated flag and a note; `meta.codebook` is the value menu the coders chose from, `meta.agreement` the counts below), made by two independent Claude (claude-fable-5-1) coders per batch, each reading id, title, description (first 700 characters), affected, attack_vector, record_type, channel; a third Claude adjudicator settled every disagreement; no human review yet; coders agreed on 28 of 33 entry points, 191 of 212 targets, 45 of 45 AI media, 498 of 564 objectives, 0 unresolved, and the script checks that the file covers exactly the records the three rules leave unstated and that no final label is 'unstated'. Four values mark records the dimension does not fit and stay visible as rows: 'no attacker: operator harm or model failure (misplaced record)' = harm with no adversary described, so the record belongs in neither population; 'none: conventional exploit record misplaced in WITH-AI' = the attack-vector label is a conventional exploit or a malicious package, so no AI medium is involved and the record is in the wrong population; 'other (tracker stub, no system named)' = a pointer to an external tracker that names no system; 'other' = an attack the coders could not fit to any codebook value; every such record keeps its population and value into step 5 (which reads `objective` from `out/methodology.json`); none is moved or dropped. `out/dataset_pre.csv` holds every ON-AI and WITH-AI record with the values after the first two steps ('unstated' kept) and `out/dataset_post.csv` the pre and post values: the dimension columns are `entry_point`, `target`, `ai_role` (= AI medium) and `objective`, empty when the dimension is not asked of the record's population, in pre as `<dim>` and `<dim>_source` (text rule / corpus label / unstated), in post as `<dim>_pre`, `<dim>_post`, `<dim>_how` and `<dim>_review` (confirmed / corrected / kept with dissent / not reviewed) plus `coded_note` ('dimension: reason' from the coders or the reviewers), and `dependency` holds Table 4.3's value for every record of both populations; both files and `out/methodology.json` are written by `s04_methodology.py` (`make s04`), never by hand; records entered the populations by step 2's rules (Table 2.4), and by channel ON-AI has cve/ghsa 604, harm-db 370, research/other 365 records and WITH-AI cve/ghsa 80, harm-db 1,370, research/other 10 (channel columns are % of that channel, so each 10.0 in WITH-AI's research/other column is one record).

Conventions, 95% CI, pooled rows and the glossary: `out/s01_overview.md` section 0.

**Table 4.0. How each value was assigned** (ON-AI n = 1,339; WITH-AI n = 1,460)

Counts of records per dimension by the step that fixed the value (the four step columns sum to the records); the last column counts records holding one of the four residue values defined above, whichever step set them. In the notes of Tables 4.1–4.5, 'rule' = label-group rule, 'coded' = coded from text, 'review' = corrected by review, and * marks a value that did not exist before this step.

| dimension (table) | records | text rule | corpus label | label-group rule | coded from text (coders agreed / adjudicated) | corrected by review | value 'other', 'no attacker' or 'none' |
|---|---|---|---|---|---|---|---|
| ON-AI entry point (4.1) | 1,339 | 341 (25.5%) | 126 (9.4%) | 207 (15.5%) | 30 (2.2%) (25 / 5) | 635 (47.4%) | 199 (14.9%) |
| ON-AI target (4.2) | 1,339 | 702 (52.4%) | 0 (0.0%) | 24 (1.8%) | 197 (14.7%) (180 / 17) | 416 (31.1%) | 258 (19.3%) |
| WITH-AI AI medium (4.4) | 1,460 | 516 (35.3%) | 326 (22.3%) | 3 (0.2%) | 37 (2.5%) (37 / 0) | 578 (39.6%) | 342 (23.4%) |
| WITH-AI objective (4.5) | 1,460 | 725 (49.7%) | 1 (0.1%) | 0 (0.0%) | 516 (35.3%) (464 / 52) | 218 (14.9%) | 210 (14.4%) |

**Table 4.0b. Label review: two independent reviewers read 5,598 of 5,598 labels (70 value-by-step strata); both judged 3,698 correct (66.1%), 1,847 were corrected, 53 stayed as assigned with a dissent** (n = 5,598 labels)

Every label was read by two independent Claude reviewers given the record's title, description (first 700 characters), affected field and corpus labels, who judged it correct or proposed another value from the same codebook without seeing how it had been assigned; a third reviewer adjudicated every split. First pass: a stratified sample of 620 rule-assigned labels (up to 20 per value and assignment step, seed 20261007), reviewed and adjudicated by Claude Fable 5.1. Second pass: the remaining 4,978 labels in 55 batches of 50 records, both dimensions per record; 4,331 labels were read by two Fable 5.1 reviewers, 187 by one Fable 5.1 and one Opus 5.5 reviewer and 460 by two Opus 5.5 reviewers (the session reached its Fable usage limit), and every second-pass split was adjudicated by Opus 5.5. Third step: 21 records whose two labels disagreed on whether any adversary was described were settled by one Opus 5.5 adjudicator from the record text (21 labels changed). A label was corrected when both reviewers rejected it and agreed on the replacement, or when an adjudicator settled a split; 'disputed' = one reviewer rejected it and the adjudicator kept it. Corrections are applied in Tables 4.1–4.5 and `out/dataset_post.csv` (how = 'corrected by review'; `<dim>_review` holds every label's status). Every label was read, so the per-value counts are exact: the share judged correct is the precision of that assignment step for that value.

| dimension | value | how assigned | records with this label | reviewed | both reviewers: correct | corrected (to) | disputed |
|---|---|---|---|---|---|---|---|
| AI medium | deepfake, medium not stated | coded from text | 1 | 1 | 1 (100.0%) | 0 | 0 |
| AI medium | deepfake, medium not stated | corpus label | 605 | 605 | 320 (52.9%) | 280 (no attacker: operator harm or model failure (misplaced record) 88, synthetic video 54, synthetic audio/voice 45, none: conventional exploit record misplaced in WITH-AI 38, other 33, synthetic image 14, generated text (phishing / lures / disinformation) 7, generated or assisted code (malware / tooling) 1) | 5 |
| AI medium | generated or assisted code (malware / tooling) | text rule | 9 | 9 | 7 (77.8%) | 2 (deepfake, medium not stated 1, generated text (phishing / lures / disinformation) 1) | 0 |
| AI medium | generated text (phishing / lures / disinformation) | coded from text | 1 | 1 | 1 (100.0%) | 0 | 0 |
| AI medium | generated text (phishing / lures / disinformation) | text rule | 114 | 114 | 42 (36.8%) | 71 (none: conventional exploit record misplaced in WITH-AI 30, deepfake, medium not stated 15, no attacker: operator harm or model failure (misplaced record) 13, synthetic video 6, other 6, synthetic audio/voice 1) | 1 |
| AI medium | no attacker: operator harm or model failure (misplaced record) | coded from text | 3 | 3 | 3 (100.0%) | 0 | 0 |
| AI medium | none: conventional exploit record misplaced in WITH-AI | label-group rule | 60 | 60 | 3 (5.0%) | 57 (other 29, no attacker: operator harm or model failure (misplaced record) 16, deepfake, medium not stated 6, synthetic video 4, synthetic image 1, generated text (phishing / lures / disinformation) 1) | 0 |
| AI medium | other | coded from text | 25 | 25 | 18 (72.0%) | 7 (no attacker: operator harm or model failure (misplaced record) 7) | 0 |
| AI medium | reconnaissance / planning / orchestration | coded from text | 1 | 1 | 1 (100.0%) | 0 | 0 |
| AI medium | reconnaissance / planning / orchestration | text rule | 5 | 5 | 1 (20.0%) | 4 (no attacker: operator harm or model failure (misplaced record) 3, other 1) | 0 |
| AI medium | synthetic audio/voice | coded from text | 3 | 3 | 3 (100.0%) | 0 | 0 |
| AI medium | synthetic audio/voice | text rule | 241 | 241 | 147 (61.0%) | 77 (synthetic video 73, deepfake, medium not stated 3, other 1) | 17 |
| AI medium | synthetic image | corpus label | 2 | 2 | 1 (50.0%) | 1 (no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| AI medium | synthetic image | text rule | 276 | 276 | 209 (75.7%) | 67 (no attacker: operator harm or model failure (misplaced record) 36, deepfake, medium not stated 18, none: conventional exploit record misplaced in WITH-AI 10, synthetic video 2, generated text (phishing / lures / disinformation) 1) | 0 |
| AI medium | synthetic video | coded from text | 11 | 11 | 10 (90.9%) | 1 (no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| AI medium | synthetic video | text rule | 103 | 103 | 92 (89.3%) | 11 (deepfake, medium not stated 5, no attacker: operator harm or model failure (misplaced record) 5, synthetic image 1) | 0 |
| entry point | adversarial input to a classifier | corpus label | 56 | 56 | 25 (44.6%) | 31 (no attacker: operator harm or model failure (misplaced record) 19, other 4, poisoned training data or model 3, indirect carrier (web/email/doc/tool output) 2, malicious package / model / skill (supply chain) 1, stolen or leaked credential 1, query access to the model (extraction / inference) 1) | 0 |
| entry point | adversarial input to a classifier | text rule | 21 | 21 | 17 (81.0%) | 4 (via the agent's tools or sandbox 2, direct prompt by the user 1, poisoned training data or model 1) | 0 |
| entry point | direct prompt by the user | coded from text | 3 | 3 | 3 (100.0%) | 0 | 0 |
| entry point | direct prompt by the user | text rule | 328 | 328 | 163 (49.7%) | 161 (prompt injection, carrier not stated 57, indirect carrier (web/email/doc/tool output) 38, exploit of a conventional software vulnerability 28, no attacker: operator harm or model failure (misplaced record) 17, other 4, poisoned training data or model 4, exposed / misconfigured service 4, adversarial input to a classifier 2, malicious package / model / skill (supply chain) 2, stolen or leaked credential 2, via the agent's tools or sandbox 2, query access to the model (extraction / inference) 1) | 4 |
| entry point | exploit of a conventional software vulnerability | coded from text | 19 | 19 | 19 (100.0%) | 0 | 0 |
| entry point | exploit of a conventional software vulnerability | label-group rule | 287 | 287 | 163 (56.8%) | 121 (no attacker: operator harm or model failure (misplaced record) 46, other 44, malicious package / model / skill (supply chain) 10, direct prompt by the user 6, exposed / misconfigured service 5, via the agent's tools or sandbox 3, prompt injection, carrier not stated 2, adversarial input to a classifier 2, indirect carrier (web/email/doc/tool output) 2, stolen or leaked credential 1) | 3 |
| entry point | exposed / misconfigured service | coded from text | 1 | 1 | 1 (100.0%) | 0 | 0 |
| entry point | exposed / misconfigured service | text rule | 48 | 48 | 19 (39.6%) | 29 (exploit of a conventional software vulnerability 22, via the agent's tools or sandbox 3, no attacker: operator harm or model failure (misplaced record) 2, indirect carrier (web/email/doc/tool output) 1, direct prompt by the user 1) | 0 |
| entry point | indirect carrier (web/email/doc/tool output) | coded from text | 1 | 1 | 1 (100.0%) | 0 | 0 |
| entry point | indirect carrier (web/email/doc/tool output) | corpus label | 1 | 1 | 1 (100.0%) | 0 | 0 |
| entry point | indirect carrier (web/email/doc/tool output) | text rule | 194 | 194 | 102 (52.6%) | 90 (exploit of a conventional software vulnerability 49, malicious package / model / skill (supply chain) 8, via the agent's tools or sandbox 7, exposed / misconfigured service 7, prompt injection, carrier not stated 5, other 4, direct prompt by the user 3, poisoned training data or model 2, query access to the model (extraction / inference) 2, adversarial input to a classifier 2, no attacker: operator harm or model failure (misplaced record) 1) | 2 |
| entry point | malicious package / model / skill (supply chain) | corpus label | 98 | 98 | 79 (80.6%) | 18 (poisoned training data or model 12, other 3, indirect carrier (web/email/doc/tool output) 2, direct prompt by the user 1) | 1 |
| entry point | malicious package / model / skill (supply chain) | text rule | 33 | 33 | 24 (72.7%) | 8 (exploit of a conventional software vulnerability 3, no attacker: operator harm or model failure (misplaced record) 2, poisoned training data or model 1, stolen or leaked credential 1, exposed / misconfigured service 1) | 1 |
| entry point | no attacker: operator harm or model failure (misplaced record) | coded from text | 3 | 3 | 3 (100.0%) | 0 | 0 |
| entry point | poisoned training data or model | label-group rule | 21 | 21 | 10 (47.6%) | 11 (no attacker: operator harm or model failure (misplaced record) 7, malicious package / model / skill (supply chain) 2, other 1, exploit of a conventional software vulnerability 1) | 0 |
| entry point | prompt injection, carrier not stated | corpus label | 80 | 80 | 20 (25.0%) | 60 (no attacker: operator harm or model failure (misplaced record) 24, direct prompt by the user 12, exploit of a conventional software vulnerability 11, indirect carrier (web/email/doc/tool output) 7, query access to the model (extraction / inference) 2, via the agent's tools or sandbox 2, adversarial input to a classifier 1, stolen or leaked credential 1) | 0 |
| entry point | query access to the model (extraction / inference) | label-group rule | 11 | 11 | 9 (81.8%) | 2 (other 1, no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| entry point | stolen or leaked credential | coded from text | 1 | 1 | 0 (0.0%) | 1 (exploit of a conventional software vulnerability 1) | 0 |
| entry point | stolen or leaked credential | text rule | 62 | 62 | 8 (12.9%) | 53 (exploit of a conventional software vulnerability 26, exposed / misconfigured service 11, indirect carrier (web/email/doc/tool output) 4, no attacker: operator harm or model failure (misplaced record) 4, malicious package / model / skill (supply chain) 3, via the agent's tools or sandbox 2, prompt injection, carrier not stated 1, adversarial input to a classifier 1, other 1) | 1 |
| entry point | via the agent's tools or sandbox | coded from text | 5 | 5 | 3 (60.0%) | 2 (exploit of a conventional software vulnerability 2) | 0 |
| entry point | via the agent's tools or sandbox | label-group rule | 66 | 66 | 22 (33.3%) | 44 (exploit of a conventional software vulnerability 25, direct prompt by the user 8, other 8, no attacker: operator harm or model failure (misplaced record) 3) | 0 |
| objective | defamation / impersonation of a person | coded from text | 73 | 73 | 61 (83.6%) | 12 (financial fraud / extortion 10, public deception, not political (hoax, fake news, clickbait) 1, no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| objective | defamation / impersonation of a person | text rule | 84 | 84 | 22 (26.2%) | 61 (intrusion / cyber operation 38, political / influence 9, public deception, not political (hoax, fake news, clickbait) 6, financial fraud / extortion 3, no attacker: operator harm or model failure (misplaced record) 3, non-consensual / abuse imagery 2) | 1 |
| objective | financial fraud / extortion | coded from text | 14 | 14 | 14 (100.0%) | 0 | 0 |
| objective | financial fraud / extortion | text rule | 455 | 455 | 407 (89.5%) | 47 (no attacker: operator harm or model failure (misplaced record) 20, intrusion / cyber operation 14, non-consensual / abuse imagery 7, political / influence 4, other 2) | 1 |
| objective | harassment or humiliation of a private person | coded from text | 17 | 17 | 17 (100.0%) | 0 | 0 |
| objective | intrusion / cyber operation | coded from text | 61 | 61 | 61 (100.0%) | 0 | 0 |
| objective | intrusion / cyber operation | text rule | 34 | 34 | 26 (76.5%) | 7 (no attacker: operator harm or model failure (misplaced record) 3, political / influence 3, public deception, not political (hoax, fake news, clickbait) 1) | 1 |
| objective | no attacker: operator harm or model failure (misplaced record) | coded from text | 103 | 103 | 97 (94.2%) | 6 (defamation / impersonation of a person 3, intrusion / cyber operation 3) | 0 |
| objective | non-consensual / abuse imagery | coded from text | 63 | 63 | 62 (98.4%) | 1 (no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| objective | non-consensual / abuse imagery | corpus label | 3 | 3 | 1 (33.3%) | 2 (no attacker: operator harm or model failure (misplaced record) 2) | 0 |
| objective | non-consensual / abuse imagery | text rule | 150 | 150 | 118 (78.7%) | 30 (no attacker: operator harm or model failure (misplaced record) 23, intrusion / cyber operation 5, public deception, not political (hoax, fake news, clickbait) 1, financial fraud / extortion 1) | 2 |
| objective | other | coded from text | 61 | 61 | 34 (55.7%) | 26 (no attacker: operator harm or model failure (misplaced record) 13, intrusion / cyber operation 7, defamation / impersonation of a person 3, political / influence 2, public deception, not political (hoax, fake news, clickbait) 1) | 1 |
| objective | political / influence | coded from text | 114 | 114 | 113 (99.1%) | 1 (no attacker: operator harm or model failure (misplaced record) 1) | 0 |
| objective | political / influence | text rule | 170 | 170 | 147 (86.5%) | 23 (no attacker: operator harm or model failure (misplaced record) 9, defamation / impersonation of a person 5, intrusion / cyber operation 4, public deception, not political (hoax, fake news, clickbait) 2, non-consensual / abuse imagery 2, financial fraud / extortion 1) | 0 |
| objective | public deception, not political (hoax, fake news, clickbait) | coded from text | 58 | 58 | 56 (96.6%) | 2 (financial fraud / extortion 2) | 0 |
| target | ML/LLM framework or serving library | coded from text | 34 | 34 | 28 (82.4%) | 6 (other 3, consumer chatbot / hosted LLM app 1, agent / copilot / coding assistant / MCP 1, detection / classification model 1) | 0 |
| target | ML/LLM framework or serving library | text rule | 19 | 19 | 18 (94.7%) | 1 (other 1) | 0 |
| target | RAG / vector / memory store | coded from text | 1 | 1 | 1 (100.0%) | 0 | 0 |
| target | RAG / vector / memory store | text rule | 10 | 10 | 8 (80.0%) | 2 (model hub / training pipeline / weights 1, a model itself (vision, speech or text model attacked directly) 1) | 0 |
| target | a model itself (vision, speech or text model attacked directly) | coded from text | 33 | 33 | 28 (84.8%) | 5 (no attacker: operator harm or model failure (misplaced record) 3, consumer chatbot / hosted LLM app 2) | 0 |
| target | a non-AI application with an AI feature (web app, CMS plugin, SaaS) | coded from text | 9 | 9 | 9 (100.0%) | 0 | 0 |
| target | a physical or embedded AI system (vehicle, robot, device) | coded from text | 1 | 1 | 1 (100.0%) | 0 | 0 |
| target | agent / copilot / coding assistant / MCP | coded from text | 29 | 29 | 29 (100.0%) | 0 | 0 |
| target | agent / copilot / coding assistant / MCP | text rule | 626 | 626 | 549 (87.7%) | 74 (no attacker: operator harm or model failure (misplaced record) 20, a non-AI application with an AI feature (web app, CMS plugin, SaaS) 13, consumer chatbot / hosted LLM app 10, a model itself (vision, speech or text model attacked directly) 10, other 10, RAG / vector / memory store 4, ML/LLM framework or serving library 4, model hub / training pipeline / weights 2, a physical or embedded AI system (vehicle, robot, device) 1) | 3 |
| target | consumer chatbot / hosted LLM app | coded from text | 24 | 24 | 23 (95.8%) | 1 (agent / copilot / coding assistant / MCP 1) | 0 |
| target | consumer chatbot / hosted LLM app | text rule | 237 | 237 | 73 (30.8%) | 162 (a model itself (vision, speech or text model attacked directly) 102, no attacker: operator harm or model failure (misplaced record) 23, agent / copilot / coding assistant / MCP 15, ML/LLM framework or serving library 8, model hub / training pipeline / weights 8, other 3, a non-AI application with an AI feature (web app, CMS plugin, SaaS) 2, detection / classification model 1) | 2 |
| target | detection / classification model | coded from text | 15 | 15 | 15 (100.0%) | 0 | 0 |
| target | detection / classification model | text rule | 45 | 45 | 25 (55.6%) | 19 (other 8, no attacker: operator harm or model failure (misplaced record) 7, consumer chatbot / hosted LLM app 2, model hub / training pipeline / weights 1, a model itself (vision, speech or text model attacked directly) 1) | 1 |
| target | model hub / training pipeline / weights | coded from text | 14 | 14 | 14 (100.0%) | 0 | 0 |
| target | model hub / training pipeline / weights | text rule | 41 | 41 | 21 (51.2%) | 18 (a model itself (vision, speech or text model attacked directly) 5, no attacker: operator harm or model failure (misplaced record) 4, ML/LLM framework or serving library 3, RAG / vector / memory store 2, other (tracker stub, no system named) 1, agent / copilot / coding assistant / MCP 1, detection / classification model 1, other 1) | 2 |
| target | no attacker: operator harm or model failure (misplaced record) | coded from text | 12 | 12 | 12 (100.0%) | 0 | 0 |
| target | other | coded from text | 40 | 40 | 36 (90.0%) | 3 (detection / classification model 1, a model itself (vision, speech or text model attacked directly) 1, agent / copilot / coding assistant / MCP 1) | 1 |
| target | other (tracker stub, no system named) | label-group rule | 149 | 149 | 21 (14.1%) | 125 (no attacker: operator harm or model failure (misplaced record) 60, other 41, agent / copilot / coding assistant / MCP 5, a physical or embedded AI system (vehicle, robot, device) 5, a model itself (vision, speech or text model attacked directly) 5, consumer chatbot / hosted LLM app 4, a non-AI application with an AI feature (web app, CMS plugin, SaaS) 2, ML/LLM framework or serving library 1, model hub / training pipeline / weights 1, detection / classification model 1) | 3 |

**Table 4.0c. Reviewer agreement: the two reviewers settled 95.8% of labels between them; the adjudicator decided 215; 21 more were changed to make a record's two labels agree** (n = 5,598 labels)

Per dimension: labels both reviewers accepted as assigned, labels both rejected with the same replacement, splits (one accepted, or two different replacements) by how the adjudicator settled them, and labels changed afterwards because the record's other dimension said 'no attacker' and this one did not (or the reverse). The last column counts labels whose final value differs from the assigned one, by the step that had assigned it; the remaining error in Tables 4.1–4.5 is reviewer error, for which the split rate is the only measure here.

| dimension | labels | both accepted | both rejected, same replacement | split, adjudicator corrected | split, adjudicator kept | changed for consistency | changed, by the step that assigned it |
|---|---|---|---|---|---|---|---|
| entry point | 1,339 | 692 (51.7%) | 597 (44.6%) | 34 (2.5%) | 12 (0.9%) | 4 (0.3%) | text rule 345 of 686, corpus label 109 of 235, label-group rule 178 of 385, coded from text 3 of 33 |
| target | 1,339 | 911 (68.0%) | 355 (26.5%) | 59 (4.4%) | 12 (0.9%) | 2 (0.1%) | text rule 276 of 978, label-group rule 125 of 149, coded from text 15 of 212 |
| AI medium | 1,460 | 859 (58.8%) | 525 (36.0%) | 41 (2.8%) | 23 (1.6%) | 12 (0.8%) | text rule 232 of 748, corpus label 281 of 607, label-group rule 57 of 60, coded from text 8 of 45 |
| objective | 1,460 | 1,236 (84.7%) | 187 (12.8%) | 28 (1.9%) | 6 (0.4%) | 3 (0.2%) | text rule 168 of 893, corpus label 2 of 3, coded from text 48 of 564 |

**Table 4.0d. Rule value against final value, per value** (pre = the value a text rule or corpus label set, else unstated; post = the final value after every later step)

| dimension | value | pre n (%) | post n (%) | post − pre |
|---|---|---|---|---|
| entry point | exploit of a conventional software vulnerability | 0 (0.0%) | 353 (26.4%) | +353 |
| entry point | direct prompt by the user | 328 (24.5%) | 202 (15.1%) | −126 |
| entry point | indirect carrier (web/email/doc/tool output) | 195 (14.6%) | 162 (12.1%) | −33 |
| entry point | malicious package / model / skill (supply chain) | 131 (9.8%) | 131 (9.8%) | +0 |
| entry point | no attacker: operator harm or model failure (misplaced record) | 0 (0.0%) | 129 (9.6%) | +129 |
| entry point | prompt injection, carrier not stated | 80 (6.0%) | 85 (6.3%) | +5 |
| entry point | other | 0 (0.0%) | 70 (5.2%) | +70 |
| entry point | adversarial input to a classifier | 77 (5.8%) | 50 (3.7%) | −27 |
| entry point | exposed / misconfigured service | 48 (3.6%) | 48 (3.6%) | +0 |
| entry point | via the agent's tools or sandbox | 0 (0.0%) | 46 (3.4%) | +46 |
| entry point | poisoned training data or model | 0 (0.0%) | 33 (2.5%) | +33 |
| entry point | query access to the model (extraction / inference) | 0 (0.0%) | 15 (1.1%) | +15 |
| entry point | stolen or leaked credential | 62 (4.6%) | 15 (1.1%) | −47 |
| entry point | unstated | 418 (31.2%) | 0 (0.0%) | −418 |
| target | agent / copilot / coding assistant / MCP | 626 (46.8%) | 605 (45.2%) | −21 |
| target | a model itself (vision, speech or text model attacked directly) | 0 (0.0%) | 153 (11.4%) | +153 |
| target | no attacker: operator harm or model failure (misplaced record) | 0 (0.0%) | 129 (9.6%) | +129 |
| target | consumer chatbot / hosted LLM app | 237 (17.7%) | 117 (8.7%) | −120 |
| target | other | 0 (0.0%) | 104 (7.8%) | +104 |
| target | ML/LLM framework or serving library | 19 (1.4%) | 62 (4.6%) | +43 |
| target | model hub / training pipeline / weights | 41 (3.1%) | 50 (3.7%) | +9 |
| target | detection / classification model | 45 (3.4%) | 46 (3.4%) | +1 |
| target | a non-AI application with an AI feature (web app, CMS plugin, SaaS) | 0 (0.0%) | 26 (1.9%) | +26 |
| target | other (tracker stub, no system named) | 0 (0.0%) | 25 (1.9%) | +25 |
| target | RAG / vector / memory store | 10 (0.7%) | 15 (1.1%) | +5 |
| target | a physical or embedded AI system (vehicle, robot, device) | 0 (0.0%) | 7 (0.5%) | +7 |
| target | unstated | 361 (27.0%) | 0 (0.0%) | −361 |
| AI medium | deepfake, medium not stated | 605 (41.4%) | 374 (25.6%) | −231 |
| AI medium | synthetic video | 103 (7.1%) | 241 (16.5%) | +138 |
| AI medium | synthetic image | 278 (19.0%) | 226 (15.5%) | −52 |
| AI medium | synthetic audio/voice | 241 (16.5%) | 213 (14.6%) | −28 |
| AI medium | no attacker: operator harm or model failure (misplaced record) | 0 (0.0%) | 173 (11.8%) | +173 |
| AI medium | other | 0 (0.0%) | 88 (6.0%) | +88 |
| AI medium | none: conventional exploit record misplaced in WITH-AI | 0 (0.0%) | 81 (5.5%) | +81 |
| AI medium | generated text (phishing / lures / disinformation) | 114 (7.8%) | 54 (3.7%) | −60 |
| AI medium | generated or assisted code (malware / tooling) | 9 (0.6%) | 8 (0.5%) | −1 |
| AI medium | reconnaissance / planning / orchestration | 5 (0.3%) | 2 (0.1%) | −3 |
| AI medium | unstated | 105 (7.2%) | 0 (0.0%) | −105 |
| objective | financial fraud / extortion | 455 (31.2%) | 439 (30.1%) | −16 |
| objective | political / influence | 170 (11.6%) | 278 (19.0%) | +108 |
| objective | non-consensual / abuse imagery | 153 (10.5%) | 194 (13.3%) | +41 |
| objective | no attacker: operator harm or model failure (misplaced record) | 0 (0.0%) | 173 (11.8%) | +173 |
| objective | intrusion / cyber operation | 34 (2.3%) | 159 (10.9%) | +125 |
| objective | defamation / impersonation of a person | 84 (5.8%) | 95 (6.5%) | +11 |
| objective | public deception, not political (hoax, fake news, clickbait) | 0 (0.0%) | 68 (4.7%) | +68 |
| objective | other | 0 (0.0%) | 37 (2.5%) | +37 |
| objective | harassment or humiliation of a private person | 0 (0.0%) | 17 (1.2%) | +17 |
| objective | unstated | 564 (38.6%) | 0 (0.0%) | −564 |

**Table 4.1. ON-AI: how did the adversary first reach the AI system? exploit of a conventional software vulnerability 26.4%; 14.9% 'other' or 'no attacker'** (n = 1,339)

Before reclassification 418 records (31.2%) were unstated; they now hold, largest first: exploit of a conventional software vulnerability* 214 (rule 166, review 29, coded 19); no attacker: operator harm or model failure (misplaced record)* 60 (review 57, coded 3); other* 54 (review); via the agent's tools or sandbox* 28 (rule 22, review 3, coded 3); direct prompt by the user 17 (review 14, coded 3); malicious package / model / skill (supply chain) 12 (review); poisoned training data or model* 10 (rule); query access to the model (extraction / inference)* 9 (rule); exposed / misconfigured service 6 (review 5, coded 1); indirect carrier (web/email/doc/tool output) 3 (review 2, coded 1); prompt injection, carrier not stated 2 (review); adversarial input to a classifier 2 (review); stolen or leaked credential 1 (review). Review (Table 4.0b): the assigned label was correct for fewer than half of the records first given stolen or leaked credential (9 of 63), prompt injection, carrier not stated (20 of 80), via the agent's tools or sandbox (25 of 71), exposed / misconfigured service (20 of 49), poisoned training data or model (10 of 21); every label was read and the wrong ones corrected.

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| exploit of a conventional software vulnerability | 353 | 26.4 | 24.0–28.7 | 51.7 | 6.8 | 4.4 |
| direct prompt by the user | 202 | 15.1 | 13.3–17.0 | 3.8 | 25.9 | 22.7 |
| indirect carrier (web/email/doc/tool output) | 162 | 12.1 | 10.4–13.8 | 10.1 | 4.6 | 23.0 |
| malicious package / model / skill (supply chain) | 131 | 9.8 | 8.2–11.4 | 14.2 | 3.2 | 9.0 |
| no attacker: operator harm or model failure (misplaced record) | 129 | 9.6 | 8.1–11.3 | 0.3 | 31.6 | 2.7 |
| prompt injection, carrier not stated | 85 | 6.3 | 5.2–7.7 | 6.3 | 5.4 | 7.4 |
| other | 70 | 5.2 | 4.1–6.5 | 0.0 | 14.6 | 4.4 |
| adversarial input to a classifier | 50 | 3.7 | 2.7–4.8 | 0.2 | 4.3 | 9.0 |
| exposed / misconfigured service | 48 | 3.6 | 2.6–4.6 | 7.0 | 0.5 | 1.1 |
| via the agent's tools or sandbox | 46 | 3.4 | 2.5–4.5 | 6.1 | 0.0 | 2.5 |
| poisoned training data or model | 33 | 2.5 | 1.7–3.3 | 0.0 | 1.4 | 7.7 |
| query access to the model (extraction / inference) | 15 | 1.1 | 0.6–1.7 | 0.0 | 0.8 | 3.3 |
| stolen or leaked credential | 15 | 1.1 | 0.6–1.7 | 0.3 | 0.8 | 2.7 |

**Table 4.2. ON-AI: which part of the AI stack was attacked? agent / copilot / coding assistant / MCP 45.2%; 19.3% 'other' or 'no attacker'** (n = 1,339)

Before reclassification 361 records (27.0%) were unstated; they now hold, largest first: other* 81 (review 44, coded 37); no attacker: operator harm or model failure (misplaced record)* 75 (review 63, coded 12); agent / copilot / coding assistant / MCP 37 (coded 29, review 8); a model itself (vision, speech or text model attacked directly)* 34 (coded 28, review 6); consumer chatbot / hosted LLM app 30 (coded 23, review 7); ML/LLM framework or serving library 29 (coded 28, review 1); other (tracker stub, no system named)* 24 (rule); detection / classification model 18 (coded 15, review 3); model hub / training pipeline / weights 15 (coded 14, review 1); a non-AI application with an AI feature (web app, CMS plugin, SaaS)* 11 (coded 9, review 2); a physical or embedded AI system (vehicle, robot, device)* 6 (review 5, coded 1); RAG / vector / memory store 1 (coded). Review (Table 4.0b): the assigned label was correct for fewer than half of the records first given other (tracker stub, no system named) (24 of 149), consumer chatbot / hosted LLM app (98 of 261); every label was read and the wrong ones corrected.

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| agent / copilot / coding assistant / MCP | 605 | 45.2 | 42.5–47.9 | 75.8 | 8.6 | 31.5 |
| a model itself (vision, speech or text model attacked directly) | 153 | 11.4 | 9.9–13.2 | 0.0 | 19.2 | 22.5 |
| no attacker: operator harm or model failure (misplaced record) | 129 | 9.6 | 8.1–11.3 | 0.3 | 31.6 | 2.7 |
| consumer chatbot / hosted LLM app | 117 | 8.7 | 7.2–10.3 | 4.5 | 9.7 | 14.8 |
| other | 104 | 7.8 | 6.3–9.3 | 5.3 | 15.1 | 4.4 |
| ML/LLM framework or serving library | 62 | 4.6 | 3.5–5.8 | 8.3 | 0.8 | 2.5 |
| model hub / training pipeline / weights | 50 | 3.7 | 2.8–4.8 | 0.3 | 1.9 | 11.2 |
| detection / classification model | 46 | 3.4 | 2.5–4.5 | 0.5 | 3.8 | 7.9 |
| a non-AI application with an AI feature (web app, CMS plugin, SaaS) | 26 | 1.9 | 1.3–2.7 | 3.3 | 1.1 | 0.5 |
| other (tracker stub, no system named) | 25 | 1.9 | 1.2–2.6 | 0.0 | 6.8 | 0.0 |
| RAG / vector / memory store | 15 | 1.1 | 0.6–1.7 | 1.7 | 0.0 | 1.4 |
| a physical or embedded AI system (vehicle, robot, device) | 7 | 0.5 | 0.2–0.9 | 0.0 | 1.4 | 0.5 |

**Table 4.3. ON-AI: does the record carry a CVE/CWE (45%), a model-level attack vector (32%) or neither (23%)?** (n = 1,339)

Read off corpus fields, unchanged by the reclassification: a CVE or CWE id, else one of the 8 model-level attack-vector labels (prompt-injection, indirect-prompt-injection, jailbreak, adversarial-input, evasion, model-extraction, membership-inference, model-inversion), else unstated. No channel columns because every CVE/CWE record is cve/ghsa; 147 records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor.

| value | n | % | 95% CI |
|---|---|---|---|
| CVE/CWE present (software vulnerability) | 604 | 45.1 | 42.3–47.8 |
| model-level attack vector, no CVE/CWE | 422 | 31.5 | 29.1–33.9 |
| unstated | 313 | 23.4 | 21.1–25.6 |

**Table 4.4. WITH-AI: what did the AI generate: image, voice, text, video or code? deepfake, medium not stated 25.6%; 23.4% 'other', 'no attacker' or 'none'** (n = 1,460)

Before reclassification 105 records (7.2%) were unstated; they now hold, largest first: other* 47 (review 29, coded 18); no attacker: operator harm or model failure (misplaced record)* 27 (review 24, coded 3); synthetic video 14 (coded 10, review 4); deepfake, medium not stated 7 (review 6, coded 1); synthetic audio/voice 3 (coded); none: conventional exploit record misplaced in WITH-AI* 3 (rule); generated text (phishing / lures / disinformation) 2 (coded 1, review 1); reconnaissance / planning / orchestration 1 (coded); synthetic image 1 (review). Review (Table 4.0b): the assigned label was correct for fewer than half of the records first given none: conventional exploit record misplaced in WITH-AI (3 of 60), reconnaissance / planning / orchestration (2 of 6), generated text (phishing / lures / disinformation) (44 of 115); every label was read and the wrong ones corrected.

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| deepfake, medium not stated | 374 | 25.6 | 23.4–27.7 | 0.0 | 27.3 | 0.0 |
| synthetic video | 241 | 16.5 | 14.7–18.4 | 0.0 | 17.5 | 10.0 |
| synthetic image | 226 | 15.5 | 13.7–17.4 | 0.0 | 16.4 | 10.0 |
| synthetic audio/voice | 213 | 14.6 | 12.8–16.4 | 0.0 | 15.3 | 30.0 |
| no attacker: operator harm or model failure (misplaced record) | 173 | 11.8 | 10.1–13.6 | 0.0 | 12.6 | 10.0 |
| other | 88 | 6.0 | 4.9–7.3 | 0.0 | 6.4 | 0.0 |
| none: conventional exploit record misplaced in WITH-AI | 81 | 5.5 | 4.4–6.7 | 100.0 | 0.1 | 0.0 |
| generated text (phishing / lures / disinformation) | 54 | 3.7 | 2.8–4.7 | 0.0 | 3.7 | 30.0 |
| generated or assisted code (malware / tooling) | 8 | 0.5 | 0.2–1.0 | 0.0 | 0.5 | 10.0 |
| reconnaissance / planning / orchestration | 2 | 0.1 | 0.0–0.3 | 0.0 | 0.1 | 0.0 |

**Table 4.5. WITH-AI: what was the attacker after? financial fraud / extortion 30.1%; 14.4% 'other' or 'no attacker'** (n = 1,460)

Before reclassification 564 records (38.6%) were unstated; they now hold, largest first: political / influence 115 (coded 113, review 2); no attacker: operator harm or model failure (misplaced record)* 113 (coded 97, review 16); intrusion / cyber operation 71 (coded 61, review 10); defamation / impersonation of a person 67 (coded 61, review 6); non-consensual / abuse imagery 62 (coded); public deception, not political (hoax, fake news, clickbait)* 58 (coded 56, review 2); other* 35 (coded); financial fraud / extortion 26 (coded 14, review 12); harassment or humiliation of a private person* 17 (coded).

| value | n | % | 95% CI | % in cve/ghsa | % in harm-db | % in research/other |
|---|---|---|---|---|---|---|
| financial fraud / extortion | 439 | 30.1 | 27.8–32.4 | 0.0 | 31.8 | 40.0 |
| political / influence | 278 | 19.0 | 17.0–21.1 | 0.0 | 20.1 | 30.0 |
| non-consensual / abuse imagery | 194 | 13.3 | 11.6–15.1 | 0.0 | 14.2 | 0.0 |
| no attacker: operator harm or model failure (misplaced record) | 173 | 11.8 | 10.1–13.6 | 0.0 | 12.6 | 10.0 |
| intrusion / cyber operation | 159 | 10.9 | 9.3–12.5 | 100.0 | 5.6 | 20.0 |
| defamation / impersonation of a person | 95 | 6.5 | 5.3–7.8 | 0.0 | 6.9 | 0.0 |
| public deception, not political (hoax, fake news, clickbait) | 68 | 4.7 | 3.6–5.8 | 0.0 | 5.0 | 0.0 |
| other | 37 | 2.5 | 1.8–3.4 | 0.0 | 2.7 | 0.0 |
| harassment or humiliation of a private person | 17 | 1.2 | 0.7–1.7 | 0.0 | 1.2 | 0.0 |
