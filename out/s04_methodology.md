# Step 4 — Entry point, target, AI medium and objective (reviewed data)

Each ON-AI record has an entry point (Table 4.1) and a target (4.2); each WITH-AI record has an AI medium (4.4) and an attacker objective (4.5). These are the cleaned labels that every later step uses.

**How the labels were made.** Keyword rules on the title, description and affected field set a first value (the lists ENTRY, TARGET, AIROLE and OBJECTIVE in `s04_methodology.py`); where none matched, the corpus attack-vector label set it if that label maps to a single value, then a label-group rule (a group of attack-vector labels, or for the target a tracker-stub description), and the records still without a value were labelled from the text by two independent coders with an adjudicator (`coded/relabels.json`; the coders agreed on 28 of 33 entry points, 191 of 212 targets, 45 of 45 AI media, 498 of 564 objectives).

**How the labels were reviewed.** Every one of the 5,598 labels was then read by two independent reviewers who saw the record's title, description, affected field and corpus labels but not how the label had been set. Each judged the label correct or proposed another value from the same list. When the two disagreed, an adjudicator decided; a final pass made each record's two labels agree on whether any adversary is described. Table 4.0 gives the agreement; `coded/review.json` holds every decision and `coded/review_verdicts.json` every reviewer's verdict and note. Step 6 compares these labels with the first values (keyword rule or corpus attack-vector label).

**Values that mark a misplaced or unplaceable record.** They stay visible in Tables 4.1, 4.2, 4.4 and 4.5. Only the first two mark a misplaced record, and step 5 leaves those out (129 ON-AI and 254 WITH-AI records):

- *no attacker: operator harm or model failure (misplaced record)*: no adversary is described (a product failure, policy, court, lawsuit, deployment or benchmark story).
- *none: conventional exploit record misplaced in WITH-AI*: a conventional-exploit or malicious-package record placed in WITH-AI (80 cve/ghsa, 1 harm-db); no AI medium is involved. In Table 4.5 these records carry the objective 'intrusion / cyber operation' (81 of that row's 159).
- *other (tracker stub, no system named)*: a pointer to an external tracker that names no attacked system.
- *other*: an adversary is described but no value fits, for instance an AI-assisted scam whose victim is not an AI system.

**Files.** `out/dataset_post.csv` holds every ON-AI and WITH-AI record with its reviewed labels (`<dim>_post`) and the coder's or reviewer's note (`coded_note`); its audit columns (`<dim>_pre`, `<dim>_how`, `<dim>_review`) are explained in the README. `out/dataset_post_2026.csv` holds its 2026 rows; `out/dataset_pre.csv` holds the first values step 6 compares with. The dimensions are `entry_point`, `target`, `ai_role` (= AI medium) and `objective`, empty when not asked of the record's population; `dependency` holds Table 4.3's value. All files are written by `s04_methodology.py` (`make s04`), never by hand.

Records entered the populations by step 2's rules (Table 2.4). By channel ON-AI has cve/ghsa 604, harm-db 370, research/other 365 records and WITH-AI cve/ghsa 80, harm-db 1,370, research/other 10 (channel columns are % of that channel, so each 10.0 in WITH-AI's research/other column is one record).

Conventions, 95% CI, pooled rows and the glossary: `out/s01_overview.md` section 0.

**Table 4.0. Review: the two reviewers reached the same label on 95.8% of 5,598 labels without the adjudicator** (n = labels)

*Same label* = both reviewers ended on the same value; *adjudicated* = they differed and the adjudicator chose; *set by the final pass* = labels the last adjudicator decided so that the record's two labels agree on whether an adversary is described. The adjudicated share is the only measure here of how far reviewers could disagree. Reviewers: two Claude Fable 5.1 reviewers read 4,951 labels (620 of them first, as a stratified sample); one Fable 5.1 and one Claude Opus 5.5 read 187, and two Opus 5.5 read 460 after a usage limit. The adjudicator was Fable 5.1 for the first 620 labels and Opus 5.5 for the rest and the final pass.

| dimension | labels | reviewers reached the same label | adjudicated | set by the final pass |
|---|---|---|---|---|
| ON-AI entry point | 1,339 | 1,289 (96.3%) | 46 (3.4%) | 4 |
| ON-AI target | 1,339 | 1,266 (94.5%) | 71 (5.3%) | 2 |
| WITH-AI AI medium | 1,460 | 1,384 (94.8%) | 64 (4.4%) | 12 |
| WITH-AI objective | 1,460 | 1,423 (97.5%) | 34 (2.3%) | 3 |
| **all four** | 5,598 | 5,362 (95.8%) | 215 (3.8%) | 21 |

**Table 4.1. ON-AI: how did the adversary first reach the AI system? exploit of a conventional software vulnerability 26.4%; 14.9% 'other' or 'no attacker'** (n = 1,339)

Reviewed values, largest first; the 'no attacker', 'none' and 'other' values are defined above.

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

Reviewed values, largest first; the 'no attacker', 'none' and 'other' values are defined above.

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

Read off corpus fields; not part of the review: a CVE or CWE id, else one of the 8 model-level attack-vector labels (prompt-injection, indirect-prompt-injection, jailbreak, adversarial-input, evasion, model-extraction, membership-inference, model-inversion), else unstated. No channel columns because every CVE/CWE record is cve/ghsa; 147 records with both a CVE/CWE and a model-level vector are counted as CVE/CWE, so the vector share is a floor.

| value | n | % | 95% CI |
|---|---|---|---|
| CVE/CWE present (software vulnerability) | 604 | 45.1 | 42.3–47.8 |
| model-level attack vector, no CVE/CWE | 422 | 31.5 | 29.1–33.9 |
| unstated | 313 | 23.4 | 21.1–25.6 |

**Table 4.4. WITH-AI: what did the AI generate: image, voice, text, video or code? deepfake, medium not stated 25.6%; 23.4% 'other', 'no attacker' or 'none'** (n = 1,460)

Reviewed values, largest first; the 'no attacker', 'none' and 'other' values are defined above.

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

Reviewed values, largest first; the 'no attacker', 'none' and 'other' values are defined above.

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
