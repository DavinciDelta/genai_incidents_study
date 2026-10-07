# Step 4 — Entry point, target, AI medium and objective, after reclassifying the unstated records

Each ON-AI record gets an entry point (Table 4.1) and a target (4.2), each WITH-AI record an AI medium (4.4) and an attacker objective (4.5). Four assignment steps run in order, first hit wins, and every label is then reviewed:

1. **Text rule.** Ordered keyword patterns over title + description + affected (the lists ENTRY, TARGET, AIROLE and OBJECTIVE in `s04_methodology.py`).
2. **Corpus label.** The attack-vector label, where it maps to exactly one value of the dimension: malware, supply-chain, backdoor → malicious package / model / skill (supply chain) (entry point); adversarial-input, evasion → adversarial input to a classifier (entry point); indirect-prompt-injection → indirect carrier (web/email/doc/tool output) (entry point); prompt-injection, jailbreak → prompt injection, carrier not stated (entry point); csam-generation → synthetic image (AI medium); deepfake → deepfake, medium not stated (AI medium); csam-generation → non-consensual / abuse imagery (objective).
3. **Label-group rule.** A group of attack-vector labels fixes the value: conventional-exploit (auth-bypass, command-injection, csrf, data-exfiltration, deserialization, dos, info-disclosure, path-traversal, rce, sql-injection, ssrf, xss) → exploit of a conventional software vulnerability (entry point); agent (agent-hijack, memory-poisoning, sandbox-escape, tool-abuse) → via the agent's tools or sandbox (entry point); poisoning (data-poisoning, model-poisoning) → poisoned training data or model (entry point); inference (membership-inference, model-extraction, model-inversion) → query access to the model (extraction / inference) (entry point); conventional-exploit or malicious-package (backdoor, malware, supply-chain) → none: conventional exploit record misplaced in WITH-AI (AI medium). For the target, which no label names, this step is instead a tracker-stub test (a description starting 'Tracked by the OECD' or 'AI Incident Database (AIID) entry' or 'AIAAIC-tracked incident' → other (tracker stub, no system named)), placed after the keyword rules so that a system named in the text wins.
4. **Coded from text.** Records still unstated were labelled by two independent Claude (claude-fable-5-1) coders per batch, each reading id, title, description (first 700 characters), affected, attack_vector, record_type, channel; a third Claude adjudicator settled every disagreement; no human review yet; coders agreed on 28 of 33 entry points, 191 of 212 targets, 45 of 45 AI media, 498 of 564 objectives (`coded/relabels.json`; `meta.codebook` is the value menu). The script checks that the file covers exactly the records steps 1–3 leave unstated; a final 'other' safety net fired 0 times (the script stops if it fires).
5. **Review.** Two independent reviewers read every label from the record text without seeing which step set it; an adjudicator settled splits, and a last pass made each record's two labels agree on whether an adversary is described. A correction replaces the value (how = 'corrected by review'); Tables 4.0b–4.0d report it (`coded/review.json`, every verdict in `coded/review_verdicts.json`).

Four values mark records the dimension does not fit. They stay visible as rows, and none is moved or dropped (step 5 reads `objective` from `out/methodology.json`):

- *no attacker: operator harm or model failure (misplaced record)*: no adversary is described (a product failure, policy, court, lawsuit, deployment or benchmark story), so the record belongs in neither population.
- *none: conventional exploit record misplaced in WITH-AI*: a software-vulnerability record (CVE/GHSA) that step 2 placed in WITH-AI; no AI medium is involved.
- *other (tracker stub, no system named)*: a pointer to an external tracker that names no attacked system.
- *other*: an adversary is described but no value fits, for instance an AI-assisted scam in ON-AI whose victim is not an AI system.

Files, all written by `s04_methodology.py` (`make s04`), never by hand. `out/dataset_pre.csv` holds every ON-AI and WITH-AI record with the values after steps 1–2 ('unstated' kept), as `<dim>` and `<dim>_source` (text rule / corpus label / unstated). `out/dataset_post.csv` holds `<dim>_pre`, `<dim>_post`, `<dim>_how` (the step that fixed the final value) and `<dim>_review` (confirmed / corrected / kept with dissent), plus `coded_note` ('dimension: reason' from the coders or reviewers); `out/dataset_post_2026.csv` is its 2026 rows. The dimensions are `entry_point`, `target`, `ai_role` (= AI medium) and `objective`, empty when not asked of the record's population; `dependency` holds Table 4.3's value for every record.

Records entered the populations by step 2's rules (Table 2.4). By channel ON-AI has cve/ghsa 604, harm-db 370, research/other 365 records and WITH-AI cve/ghsa 80, harm-db 1,370, research/other 10 (channel columns are % of that channel, so each 10.0 in WITH-AI's research/other column is one record).

Conventions, 95% CI, pooled rows and the glossary: `out/s01_overview.md` section 0.

**Table 4.0. How each value was assigned** (ON-AI n = 1,339; WITH-AI n = 1,460)

Counts of records per dimension by the step that fixed the final value (the step columns sum to the records); the last column counts records holding one of the four residue values defined above, whichever step set them. In the notes of Tables 4.1–4.5, 'rule' = label-group rule, 'coded' = coded from text, 'review' = corrected by review, and * marks a value that did not exist before this step.

| dimension (table) | records | text rule | corpus label | label-group rule | coded from text (coders agreed / adjudicated) | corrected by review | value 'other', 'no attacker' or 'none' |
|---|---|---|---|---|---|---|---|
| ON-AI entry point (4.1) | 1,339 | 341 (25.5%) | 126 (9.4%) | 207 (15.5%) | 30 (2.2%) (25 / 5) | 635 (47.4%) | 199 (14.9%) |
| ON-AI target (4.2) | 1,339 | 702 (52.4%) | 0 (0.0%) | 24 (1.8%) | 197 (14.7%) (180 / 17) | 416 (31.1%) | 258 (19.3%) |
| WITH-AI AI medium (4.4) | 1,460 | 516 (35.3%) | 326 (22.3%) | 3 (0.2%) | 37 (2.5%) (37 / 0) | 578 (39.6%) | 342 (23.4%) |
| WITH-AI objective (4.5) | 1,460 | 725 (49.7%) | 1 (0.1%) | 0 (0.0%) | 516 (35.3%) (464 / 52) | 218 (14.9%) | 210 (14.4%) |

**Table 4.0b. Review by assignment step: 67.0% of 5,598 reviewed labels were kept, 1,847 corrected** (n = 5,598 of 5,598 labels)

Per dimension and the step that had assigned the label: how many labels that step set, how many the review read, how many it kept (both reviewers accepted, or the adjudicator kept it over one dissent) and how many it corrected, with the two most common replacements. Every label was read, so 'kept' is the precision of that step. Per-value detail: Table 4.0d.

| dimension | assigned by | labels | reviewed | kept | corrected | main replacements |
|---|---|---|---|---|---|---|
| entry point | text rule | 686 | 686 | 341 (49.7%) | 345 | exploit of a conventional software vulnerability 128, prompt injection, carrier not stated 63 |
| entry point | corpus label | 235 | 235 | 126 (53.6%) | 109 | no attacker: operator harm or model failure (misplaced record) 43, poisoned training data or model 15 |
| entry point | label-group rule | 385 | 385 | 207 (53.8%) | 178 | no attacker: operator harm or model failure (misplaced record) 57, other 54 |
| entry point | coded from text | 33 | 33 | 30 (90.9%) | 3 | exploit of a conventional software vulnerability 3 |
| target | text rule | 978 | 978 | 702 (71.8%) | 276 | a model itself (vision, speech or text model attacked directly) 119, no attacker: operator harm or model failure (misplaced record) 54 |
| target | label-group rule | 149 | 149 | 24 (16.1%) | 125 | no attacker: operator harm or model failure (misplaced record) 60, other 41 |
| target | coded from text | 212 | 212 | 197 (92.9%) | 15 | other 3, consumer chatbot / hosted LLM app 3 |
| AI medium | text rule | 748 | 748 | 516 (69.0%) | 232 | synthetic video 81, no attacker: operator harm or model failure (misplaced record) 57 |
| AI medium | corpus label | 607 | 607 | 326 (53.7%) | 281 | no attacker: operator harm or model failure (misplaced record) 89, synthetic video 54 |
| AI medium | label-group rule | 60 | 60 | 3 (5.0%) | 57 | other 29, no attacker: operator harm or model failure (misplaced record) 16 |
| AI medium | coded from text | 45 | 45 | 37 (82.2%) | 8 | no attacker: operator harm or model failure (misplaced record) 8 |
| objective | text rule | 893 | 893 | 725 (81.2%) | 168 | intrusion / cyber operation 61, no attacker: operator harm or model failure (misplaced record) 58 |
| objective | corpus label | 3 | 3 | 1 (33.3%) | 2 | no attacker: operator harm or model failure (misplaced record) 2 |
| objective | coded from text | 564 | 564 | 516 (91.5%) | 48 | no attacker: operator harm or model failure (misplaced record) 16, financial fraud / extortion 12 |
| **all four** | text rule | 3,305 | 3,305 | 2,284 (69.1%) | 1,021 | |
| **all four** | corpus label | 845 | 845 | 453 (53.6%) | 392 | |
| **all four** | label-group rule | 594 | 594 | 234 (39.4%) | 360 | |
| **all four** | coded from text | 854 | 854 | 780 (91.3%) | 74 | |

**Table 4.0c. Reviewer agreement: the two reviewers settled 95.8% of labels between them; the adjudicator decided 215; 21 more were changed to make a record's two labels agree** (n = 5,598 labels)

Every label was read by two independent Claude reviewers given the record's title, description (first 700 characters), affected field and corpus labels, who judged it correct or proposed another value from the same codebook without seeing how it had been assigned; a third reviewer adjudicated every split. First pass: a stratified sample of 620 rule-assigned labels (up to 20 per value and assignment step, seed 20261007), reviewed and adjudicated by Claude Fable 5.1. Second pass: the remaining 4,978 labels in 55 batches of 50 records, both dimensions per record; 4,331 labels were read by two Fable 5.1 reviewers, 187 by one Fable 5.1 and one Opus 5.5 reviewer and 460 by two Opus 5.5 reviewers (the session reached its Fable usage limit), and every second-pass split was adjudicated by Opus 5.5. Third step: 21 records whose two labels disagreed on whether any adversary was described were settled by one Opus 5.5 adjudicator from the record text (21 labels changed). Columns: labels both reviewers accepted, labels both rejected with the same replacement, splits (one accepted, or two different replacements) by how the adjudicator settled them, and labels changed afterwards because the record's other dimension said 'no attacker' and this one did not (or the reverse). The remaining error in Tables 4.1–4.5 is reviewer error, for which the split rate is the only measure here; every reviewer verdict and note is in `coded/review_verdicts.json`.

| dimension | labels | both accepted | both rejected, same replacement | split, adjudicator corrected | split, adjudicator kept | changed for consistency |
|---|---|---|---|---|---|---|
| entry point | 1,339 | 692 (51.7%) | 597 (44.6%) | 34 (2.5%) | 12 (0.9%) | 4 (0.3%) |
| target | 1,339 | 911 (68.0%) | 355 (26.5%) | 59 (4.4%) | 12 (0.9%) | 2 (0.1%) |
| AI medium | 1,460 | 859 (58.8%) | 525 (36.0%) | 41 (2.8%) | 23 (1.6%) | 12 (0.8%) |
| objective | 1,460 | 1,236 (84.7%) | 187 (12.8%) | 28 (1.9%) | 6 (0.4%) | 3 (0.2%) |

**Table 4.0d. Each value from rule to final** (per dimension, largest final value first)

*Pre* = the value a text rule or corpus label set, as in `out/dataset_pre.csv` ('unstated' otherwise); *before review* = the value after the label-group rule and the coders; *kept* = labels the review left in place; *moved out* = labels the review took away, with where most went; *moved in* = labels the review gave this value; *final* = kept + moved in, the value in Tables 4.1–4.5 and `out/dataset_post.csv`.

| dimension | value | pre | before review | kept | moved out (main destinations) | moved in | final n (%) |
|---|---|---|---|---|---|---|---|
| entry point | exploit of a conventional software vulnerability | 0 | 306 | 185 | 121 (no attacker: operator harm or model failure (misplaced record) 46, other 44) | 168 | 353 (26.4%) |
| entry point | direct prompt by the user | 328 | 331 | 170 | 161 (prompt injection, carrier not stated 57, indirect carrier (web/email/doc/tool output) 38) | 32 | 202 (15.1%) |
| entry point | indirect carrier (web/email/doc/tool output) | 195 | 196 | 106 | 90 (exploit of a conventional software vulnerability 49, malicious package / model / skill (supply chain) 8) | 56 | 162 (12.1%) |
| entry point | malicious package / model / skill (supply chain) | 131 | 131 | 105 | 26 (poisoned training data or model 13, exploit of a conventional software vulnerability 3) | 26 | 131 (9.8%) |
| entry point | no attacker: operator harm or model failure (misplaced record) | 0 | 3 | 3 | 0 | 126 | 129 (9.6%) |
| entry point | prompt injection, carrier not stated | 80 | 80 | 20 | 60 (no attacker: operator harm or model failure (misplaced record) 24, direct prompt by the user 12) | 65 | 85 (6.3%) |
| entry point | other | 0 | 0 | 0 | 0 | 70 | 70 (5.2%) |
| entry point | adversarial input to a classifier | 77 | 77 | 42 | 35 (no attacker: operator harm or model failure (misplaced record) 19, poisoned training data or model 4) | 8 | 50 (3.7%) |
| entry point | exposed / misconfigured service | 48 | 49 | 20 | 29 (exploit of a conventional software vulnerability 22, via the agent's tools or sandbox 3) | 28 | 48 (3.6%) |
| entry point | via the agent's tools or sandbox | 0 | 71 | 25 | 46 (exploit of a conventional software vulnerability 27, other 8) | 21 | 46 (3.4%) |
| entry point | poisoned training data or model | 0 | 21 | 10 | 11 (no attacker: operator harm or model failure (misplaced record) 7, malicious package / model / skill (supply chain) 2) | 23 | 33 (2.5%) |
| entry point | query access to the model (extraction / inference) | 0 | 11 | 9 | 2 (no attacker: operator harm or model failure (misplaced record) 1, other 1) | 6 | 15 (1.1%) |
| entry point | stolen or leaked credential | 62 | 63 | 9 | 54 (exploit of a conventional software vulnerability 27, exposed / misconfigured service 11) | 6 | 15 (1.1%) |
| entry point | unstated | 418 | 0 | 0 | 0 | 0 | 0 (0.0%) |
| target | agent / copilot / coding assistant / MCP | 626 | 655 | 581 | 74 (no attacker: operator harm or model failure (misplaced record) 20, a non-AI application with an AI feature (web app, CMS plugin, SaaS) 13) | 24 | 605 (45.2%) |
| target | a model itself (vision, speech or text model attacked directly) | 0 | 33 | 28 | 5 (no attacker: operator harm or model failure (misplaced record) 3, consumer chatbot / hosted LLM app 2) | 125 | 153 (11.4%) |
| target | no attacker: operator harm or model failure (misplaced record) | 0 | 12 | 12 | 0 | 117 | 129 (9.6%) |
| target | consumer chatbot / hosted LLM app | 237 | 261 | 98 | 163 (a model itself (vision, speech or text model attacked directly) 102, no attacker: operator harm or model failure (misplaced record) 23) | 19 | 117 (8.7%) |
| target | other | 0 | 40 | 37 | 3 (detection / classification model 1, a model itself (vision, speech or text model attacked directly) 1) | 67 | 104 (7.8%) |
| target | ML/LLM framework or serving library | 19 | 53 | 46 | 7 (other 4, consumer chatbot / hosted LLM app 1) | 16 | 62 (4.6%) |
| target | model hub / training pipeline / weights | 41 | 55 | 37 | 18 (a model itself (vision, speech or text model attacked directly) 5, no attacker: operator harm or model failure (misplaced record) 4) | 13 | 50 (3.7%) |
| target | detection / classification model | 45 | 60 | 41 | 19 (other 8, no attacker: operator harm or model failure (misplaced record) 7) | 5 | 46 (3.4%) |
| target | a non-AI application with an AI feature (web app, CMS plugin, SaaS) | 0 | 9 | 9 | 0 | 17 | 26 (1.9%) |
| target | other (tracker stub, no system named) | 0 | 149 | 24 | 125 (no attacker: operator harm or model failure (misplaced record) 60, other 41) | 1 | 25 (1.9%) |
| target | RAG / vector / memory store | 10 | 11 | 9 | 2 (a model itself (vision, speech or text model attacked directly) 1, model hub / training pipeline / weights 1) | 6 | 15 (1.1%) |
| target | a physical or embedded AI system (vehicle, robot, device) | 0 | 1 | 1 | 0 | 6 | 7 (0.5%) |
| target | unstated | 361 | 0 | 0 | 0 | 0 | 0 (0.0%) |
| AI medium | deepfake, medium not stated | 605 | 606 | 326 | 280 (no attacker: operator harm or model failure (misplaced record) 88, synthetic video 54) | 48 | 374 (25.6%) |
| AI medium | synthetic video | 103 | 114 | 102 | 12 (no attacker: operator harm or model failure (misplaced record) 6, deepfake, medium not stated 5) | 139 | 241 (16.5%) |
| AI medium | synthetic image | 278 | 278 | 210 | 68 (no attacker: operator harm or model failure (misplaced record) 37, deepfake, medium not stated 18) | 16 | 226 (15.5%) |
| AI medium | synthetic audio/voice | 241 | 244 | 167 | 77 (synthetic video 73, deepfake, medium not stated 3) | 46 | 213 (14.6%) |
| AI medium | no attacker: operator harm or model failure (misplaced record) | 0 | 3 | 3 | 0 | 170 | 173 (11.8%) |
| AI medium | other | 0 | 25 | 18 | 7 (no attacker: operator harm or model failure (misplaced record) 7) | 70 | 88 (6.0%) |
| AI medium | none: conventional exploit record misplaced in WITH-AI | 0 | 60 | 3 | 57 (other 29, no attacker: operator harm or model failure (misplaced record) 16) | 78 | 81 (5.5%) |
| AI medium | generated text (phishing / lures / disinformation) | 114 | 115 | 44 | 71 (none: conventional exploit record misplaced in WITH-AI 30, deepfake, medium not stated 15) | 10 | 54 (3.7%) |
| AI medium | generated or assisted code (malware / tooling) | 9 | 9 | 7 | 2 (generated text (phishing / lures / disinformation) 1, deepfake, medium not stated 1) | 1 | 8 (0.5%) |
| AI medium | reconnaissance / planning / orchestration | 5 | 6 | 2 | 4 (no attacker: operator harm or model failure (misplaced record) 3, other 1) | 0 | 2 (0.1%) |
| AI medium | unstated | 105 | 0 | 0 | 0 | 0 | 0 (0.0%) |
| objective | financial fraud / extortion | 455 | 469 | 422 | 47 (no attacker: operator harm or model failure (misplaced record) 20, intrusion / cyber operation 14) | 17 | 439 (30.1%) |
| objective | political / influence | 170 | 284 | 260 | 24 (no attacker: operator harm or model failure (misplaced record) 10, defamation / impersonation of a person 5) | 18 | 278 (19.0%) |
| objective | non-consensual / abuse imagery | 153 | 216 | 183 | 33 (no attacker: operator harm or model failure (misplaced record) 26, intrusion / cyber operation 5) | 11 | 194 (13.3%) |
| objective | no attacker: operator harm or model failure (misplaced record) | 0 | 103 | 97 | 6 (defamation / impersonation of a person 3, intrusion / cyber operation 3) | 76 | 173 (11.8%) |
| objective | intrusion / cyber operation | 34 | 95 | 88 | 7 (political / influence 3, no attacker: operator harm or model failure (misplaced record) 3) | 71 | 159 (10.9%) |
| objective | defamation / impersonation of a person | 84 | 157 | 84 | 73 (intrusion / cyber operation 38, financial fraud / extortion 13) | 11 | 95 (6.5%) |
| objective | public deception, not political (hoax, fake news, clickbait) | 0 | 58 | 56 | 2 (financial fraud / extortion 2) | 12 | 68 (4.7%) |
| objective | other | 0 | 61 | 35 | 26 (no attacker: operator harm or model failure (misplaced record) 13, intrusion / cyber operation 7) | 2 | 37 (2.5%) |
| objective | harassment or humiliation of a private person | 0 | 17 | 17 | 0 | 0 | 17 (1.2%) |
| objective | unstated | 564 | 0 | 0 | 0 | 0 | 0 (0.0%) |

**Table 4.1. ON-AI: how did the adversary first reach the AI system? exploit of a conventional software vulnerability 26.4%; 14.9% 'other' or 'no attacker'** (n = 1,339)

Before reclassification 418 records (31.2%) were unstated; they now hold, largest first: exploit of a conventional software vulnerability* 214 (rule 166, review 29, coded 19); no attacker: operator harm or model failure (misplaced record)* 60 (review 57, coded 3); other* 54 (review); via the agent's tools or sandbox* 28 (rule 22, review 3, coded 3); direct prompt by the user 17 (review 14, coded 3); malicious package / model / skill (supply chain) 12 (review); poisoned training data or model* 10 (rule); query access to the model (extraction / inference)* 9 (rule); exposed / misconfigured service 6 (review 5, coded 1); indirect carrier (web/email/doc/tool output) 3 (review 2, coded 1); prompt injection, carrier not stated 2 (review); adversarial input to a classifier 2 (review); stolen or leaked credential 1 (review). Review (Table 4.0d): the review kept fewer than half of the labels first given stolen or leaked credential (9 of 63), prompt injection, carrier not stated (20 of 80), via the agent's tools or sandbox (25 of 71), exposed / misconfigured service (20 of 49), poisoned training data or model (10 of 21); every label was read and the wrong ones corrected.

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

Before reclassification 361 records (27.0%) were unstated; they now hold, largest first: other* 81 (review 44, coded 37); no attacker: operator harm or model failure (misplaced record)* 75 (review 63, coded 12); agent / copilot / coding assistant / MCP 37 (coded 29, review 8); a model itself (vision, speech or text model attacked directly)* 34 (coded 28, review 6); consumer chatbot / hosted LLM app 30 (coded 23, review 7); ML/LLM framework or serving library 29 (coded 28, review 1); other (tracker stub, no system named)* 24 (rule); detection / classification model 18 (coded 15, review 3); model hub / training pipeline / weights 15 (coded 14, review 1); a non-AI application with an AI feature (web app, CMS plugin, SaaS)* 11 (coded 9, review 2); a physical or embedded AI system (vehicle, robot, device)* 6 (review 5, coded 1); RAG / vector / memory store 1 (coded). Review (Table 4.0d): the review kept fewer than half of the labels first given other (tracker stub, no system named) (24 of 149), consumer chatbot / hosted LLM app (98 of 261); every label was read and the wrong ones corrected.

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

Before reclassification 105 records (7.2%) were unstated; they now hold, largest first: other* 47 (review 29, coded 18); no attacker: operator harm or model failure (misplaced record)* 27 (review 24, coded 3); synthetic video 14 (coded 10, review 4); deepfake, medium not stated 7 (review 6, coded 1); synthetic audio/voice 3 (coded); none: conventional exploit record misplaced in WITH-AI* 3 (rule); generated text (phishing / lures / disinformation) 2 (coded 1, review 1); reconnaissance / planning / orchestration 1 (coded); synthetic image 1 (review). Review (Table 4.0d): the review kept fewer than half of the labels first given none: conventional exploit record misplaced in WITH-AI (3 of 60), reconnaissance / planning / orchestration (2 of 6), generated text (phishing / lures / disinformation) (44 of 115); every label was read and the wrong ones corrected.

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
