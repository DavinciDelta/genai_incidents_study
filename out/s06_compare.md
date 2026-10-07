# Step 6 — Pre vs post: what the reclassification and the review changed, all years and 2026

*Pre* is the value step 4's first two steps gave each label (a keyword rule on the text, else the corpus attack-vector label where it maps to one value), 'unstated' otherwise: `out/dataset_pre.csv`. *Post* is the final value after the label-group rule, the two coders and the review of every label by two independent reviewers: `out/dataset_post.csv`. A label is *unchanged* when post equals pre, *filled* when pre was unstated, *replaced* when the review swapped one value for another (only the review replaces a value the first two steps set; the script checks this). *2026* = records whose corpus year is 2026 (1,416 of 2,799; `out/dataset_post_2026.csv`); the corpus year is the ingestion year for many trackers (Table 1.5), so the 2026 cut is a recent-intake cut rather than a clean incident-date cut.

Conventions, 95% CI, pooled rows and the glossary: `out/s01_overview.md` section 0.

**Table 6.1. How many labels changed between pre and post, all years and 2026** (n = labels)

Per dimension (ON-AI: entry point and target; WITH-AI: AI medium and objective). *Changed* = filled + replaced, with a bootstrap 95% CI. Filled labels had no rule value at all; replaced labels had one and the review judged it wrong.

| dimension | all years: labels | unchanged | filled | replaced | changed (95% CI) | 2026: labels | unchanged | filled | replaced | changed (95% CI) |
|---|---|---|---|---|---|---|---|---|---|---|
| entry point (ON-AI) | 1,339 | 467 (34.9%) | 418 (31.2%) | 454 (33.9%) | 65.1% (62.7–67.7) | 730 | 211 (28.9%) | 267 (36.6%) | 252 (34.5%) | 71.1% (67.7–74.4) |
| target (ON-AI) | 1,339 | 702 (52.4%) | 361 (27.0%) | 276 (20.6%) | 47.6% (44.9–50.3) | 730 | 424 (58.1%) | 177 (24.2%) | 129 (17.7%) | 41.9% (38.4–45.6) |
| AI medium (WITH-AI) | 1,460 | 842 (57.7%) | 105 (7.2%) | 513 (35.1%) | 42.3% (39.7–44.9) | 686 | 388 (56.6%) | 79 (11.5%) | 219 (31.9%) | 43.4% (39.7–46.9) |
| objective (WITH-AI) | 1,460 | 726 (49.7%) | 564 (38.6%) | 170 (11.6%) | 50.3% (47.9–52.8) | 686 | 305 (44.5%) | 300 (43.7%) | 81 (11.8%) | 55.5% (51.7–59.2) |
| **all four** | 5,598 | 2,737 (48.9%) | 1,448 (25.9%) | 1,413 (25.2%) | 51.1% (49.8–52.5) | 2,832 | 1,328 (46.9%) | 823 (29.1%) | 681 (24.0%) | 53.1% (51.2–55.0) |

Across the four dimensions 51.1% of labels changed for all years and 53.1% for 2026; replacements alone were 25.2% and 24.0%.

**Table 6.2. Share of labels changed by disclosure channel, all years and 2026** (n = labels)

The channel mix differs between the two cuts, so a different overall rate can come from the mix alone; within a channel the rates are comparable. Replaced = the review swapped a rule value; filled = there was no rule value.

| population | channel | all years: labels | filled | replaced | changed | 2026: labels | filled | replaced | changed |
|---|---|---|---|---|---|---|---|---|---|
| ON-AI | cve/ghsa | 1,208 | 26.1% | 22.5% | 48.6% | 886 | 25.1% | 23.5% | 48.5% |
| ON-AI | harm-db | 740 | 45.7% | 30.9% | 76.6% | 460 | 44.1% | 30.7% | 74.8% |
| ON-AI | research/other | 730 | 17.3% | 31.4% | 48.6% | 114 | 16.7% | 28.1% | 44.7% |
| WITH-AI | cve/ghsa | 160 | 15.0% | 78.1% | 93.1% | 70 | 22.9% | 75.7% | 98.6% |
| WITH-AI | harm-db | 2,740 | 23.5% | 20.2% | 43.7% | 1,302 | 27.9% | 19.0% | 46.9% |
| WITH-AI | research/other | 20 | 5.0% | 25.0% | 30.0% | 0 | — | — | — |

**Table 6.3. ON-AI entry point: share of each value, pre vs post, all years and 2026; largest shift: exploit of a conventional software vulnerability +26.4 points** (all years n = 1,339; 2026 n = 730)

Percent of the dimension's labels; Δ = post − pre in percentage points. The pre column keeps 'unstated', which post never holds.

| value | all years: pre % | post % | Δ | 2026: pre % | post % | Δ |
|---|---|---|---|---|---|---|
| exploit of a conventional software vulnerability | 0.0 | 26.4 | +26.4 | 0.0 | 34.8 | +34.8 |
| direct prompt by the user | 24.5 | 15.1 | −9.4 | 23.8 | 12.9 | −11.0 |
| indirect carrier (web/email/doc/tool output) | 14.6 | 12.1 | −2.5 | 13.3 | 9.7 | −3.6 |
| malicious package / model / skill (supply chain) | 9.8 | 9.8 | +0.0 | 7.1 | 8.5 | +1.4 |
| no attacker: operator harm or model failure (misplaced record) | 0.0 | 9.6 | +9.6 | 0.0 | 8.8 | +8.8 |
| prompt injection, carrier not stated | 6.0 | 6.3 | +0.4 | 5.9 | 7.1 | +1.2 |
| other | 0.0 | 5.2 | +5.2 | 0.0 | 5.9 | +5.9 |
| adversarial input to a classifier | 5.8 | 3.7 | −2.0 | 1.2 | 0.0 | −1.2 |
| exposed / misconfigured service | 3.6 | 3.6 | +0.0 | 5.3 | 6.0 | +0.7 |
| via the agent's tools or sandbox | 0.0 | 3.4 | +3.4 | 0.0 | 4.7 | +4.7 |
| poisoned training data or model | 0.0 | 2.5 | +2.5 | 0.0 | 0.7 | +0.7 |
| query access to the model (extraction / inference) | 0.0 | 1.1 | +1.1 | 0.0 | 0.4 | +0.4 |
| stolen or leaked credential | 4.6 | 1.1 | −3.5 | 6.7 | 0.5 | −6.2 |
| unstated | 31.2 | 0.0 | −31.2 | 36.6 | 0.0 | −36.6 |

**Table 6.4. ON-AI target: share of each value, pre vs post, all years and 2026; largest shift: a model itself (vision, speech or text model attacked directly) +11.4 points** (all years n = 1,339; 2026 n = 730)

Percent of the dimension's labels; Δ = post − pre in percentage points. The pre column keeps 'unstated', which post never holds.

| value | all years: pre % | post % | Δ | 2026: pre % | post % | Δ |
|---|---|---|---|---|---|---|
| agent / copilot / coding assistant / MCP | 46.8 | 45.2 | −1.6 | 59.2 | 57.5 | −1.6 |
| a model itself (vision, speech or text model attacked directly) | 0.0 | 11.4 | +11.4 | 0.0 | 10.4 | +10.4 |
| no attacker: operator harm or model failure (misplaced record) | 0.0 | 9.6 | +9.6 | 0.0 | 8.8 | +8.8 |
| consumer chatbot / hosted LLM app | 17.7 | 8.7 | −9.0 | 13.7 | 4.9 | −8.8 |
| other | 0.0 | 7.8 | +7.8 | 0.0 | 6.6 | +6.6 |
| ML/LLM framework or serving library | 1.4 | 4.6 | +3.2 | 0.3 | 3.6 | +3.3 |
| model hub / training pipeline / weights | 3.1 | 3.7 | +0.7 | 1.6 | 1.1 | −0.5 |
| detection / classification model | 3.4 | 3.4 | +0.1 | 0.3 | 0.4 | +0.1 |
| a non-AI application with an AI feature (web app, CMS plugin, SaaS) | 0.0 | 1.9 | +1.9 | 0.0 | 2.3 | +2.3 |
| other (tracker stub, no system named) | 0.0 | 1.9 | +1.9 | 0.0 | 2.7 | +2.7 |
| RAG / vector / memory store | 0.7 | 1.1 | +0.4 | 0.7 | 1.4 | +0.7 |
| a physical or embedded AI system (vehicle, robot, device) | 0.0 | 0.5 | +0.5 | 0.0 | 0.3 | +0.3 |
| unstated | 27.0 | 0.0 | −27.0 | 24.2 | 0.0 | −24.2 |

**Table 6.5. WITH-AI AI medium: share of each value, pre vs post, all years and 2026; largest shift: deepfake, medium not stated −15.8 points** (all years n = 1,460; 2026 n = 686)

Percent of the dimension's labels; Δ = post − pre in percentage points. The pre column keeps 'unstated', which post never holds.

| value | all years: pre % | post % | Δ | 2026: pre % | post % | Δ |
|---|---|---|---|---|---|---|
| deepfake, medium not stated | 41.4 | 25.6 | −15.8 | 44.0 | 26.8 | −17.2 |
| synthetic video | 7.1 | 16.5 | +9.5 | 8.0 | 13.8 | +5.8 |
| synthetic image | 19.0 | 15.5 | −3.6 | 22.9 | 17.6 | −5.2 |
| synthetic audio/voice | 16.5 | 14.6 | −1.9 | 4.7 | 5.5 | +0.9 |
| no attacker: operator harm or model failure (misplaced record) | 0.0 | 11.8 | +11.8 | 0.0 | 14.6 | +14.6 |
| other | 0.0 | 6.0 | +6.0 | 0.0 | 11.1 | +11.1 |
| none: conventional exploit record misplaced in WITH-AI | 0.0 | 5.5 | +5.5 | 0.0 | 5.2 | +5.2 |
| generated text (phishing / lures / disinformation) | 7.8 | 3.7 | −4.1 | 7.7 | 4.4 | −3.4 |
| generated or assisted code (malware / tooling) | 0.6 | 0.5 | −0.1 | 0.6 | 0.7 | +0.1 |
| reconnaissance / planning / orchestration | 0.3 | 0.1 | −0.2 | 0.6 | 0.1 | −0.4 |
| unstated | 7.2 | 0.0 | −7.2 | 11.5 | 0.0 | −11.5 |

**Table 6.6. WITH-AI objective: share of each value, pre vs post, all years and 2026; largest shift: no attacker: operator harm or model failure (misplaced record) +11.8 points** (all years n = 1,460; 2026 n = 686)

Percent of the dimension's labels; Δ = post − pre in percentage points. The pre column keeps 'unstated', which post never holds.

| value | all years: pre % | post % | Δ | 2026: pre % | post % | Δ |
|---|---|---|---|---|---|---|
| financial fraud / extortion | 31.2 | 30.1 | −1.1 | 28.0 | 27.1 | −0.9 |
| political / influence | 11.6 | 19.0 | +7.4 | 9.5 | 12.4 | +2.9 |
| non-consensual / abuse imagery | 10.5 | 13.3 | +2.8 | 11.7 | 12.7 | +1.0 |
| no attacker: operator harm or model failure (misplaced record) | 0.0 | 11.8 | +11.8 | 0.0 | 14.6 | +14.6 |
| intrusion / cyber operation | 2.3 | 10.9 | +8.6 | 1.5 | 12.7 | +11.2 |
| defamation / impersonation of a person | 5.8 | 6.5 | +0.8 | 5.7 | 9.5 | +3.8 |
| public deception, not political (hoax, fake news, clickbait) | 0.0 | 4.7 | +4.7 | 0.0 | 5.8 | +5.8 |
| other | 0.0 | 2.5 | +2.5 | 0.0 | 3.6 | +3.6 |
| harassment or humiliation of a private person | 0.0 | 1.2 | +1.2 | 0.0 | 1.6 | +1.6 |
| unstated | 38.6 | 0.0 | −38.6 | 43.7 | 0.0 | −43.7 |

**Table 6.7. The 15 largest replacements: rule value → reviewed value, and what had fired the rule** (n = replaced labels; 1,413 in all, 736 here)

*What fired* = the three most common matched words (lower-cased) when a keyword rule set the pre value (quoted), or the corpus attack-vector labels when the corpus label set it. Most replacements follow one of four patterns: an incidental keyword (a CVE whose text says 'credentials' or 'impersonate' is filed as credential theft or defamation), a product or entity name standing in for the thing attacked or produced ('GPT-4' → a chatbot; AIID's 'Synthetic Audio' entity tag → audio), the corpus label alone ('deepfake' → medium not stated) where the title names the medium or describes no attack, and a CVE carrying a harm label.

| dimension | rule value (pre) | reviewed value (post) | all years | 2026 | what fired (count) |
|---|---|---|---|---|---|
| target | consumer chatbot / hosted LLM app | a model itself (vision, speech or text model attacked directly) | 102 | 56 | “gpt-4” 27, “deepseek” 22, “claude” 18 |
| AI medium | deepfake, medium not stated | no attacker: operator harm or model failure (misplaced record) | 88 | 47 | label 'deepfake' 88 |
| AI medium | synthetic audio/voice | synthetic video | 73 | 6 | “synthetic audio” 73 |
| entry point | direct prompt by the user | prompt injection, carrier not stated | 57 | 32 | “prompt injection” 57 |
| AI medium | deepfake, medium not stated | synthetic video | 54 | 23 | label 'deepfake' 54 |
| entry point | indirect carrier (web/email/doc/tool output) | exploit of a conventional software vulnerability | 49 | 35 | “retriev” 12, “website” 11, “web page” 4 |
| AI medium | deepfake, medium not stated | synthetic audio/voice | 45 | 12 | label 'deepfake' 45 |
| AI medium | deepfake, medium not stated | none: conventional exploit record misplaced in WITH-AI | 38 | 16 | label 'deepfake' 38 |
| entry point | direct prompt by the user | indirect carrier (web/email/doc/tool output) | 38 | 17 | “prompt injection” 36, “jailbr” 1, “system prompt” 1 |
| objective | defamation / impersonation of a person | intrusion / cyber operation | 38 | 15 | “impersonat” 37, “executive” 1 |
| AI medium | synthetic image | no attacker: operator harm or model failure (misplaced record) | 37 | 20 | “sexual” 11, “image” 11, “csam” 5 |
| AI medium | deepfake, medium not stated | other | 33 | 27 | label 'deepfake' 33 |
| AI medium | generated text (phishing / lures / disinformation) | none: conventional exploit record misplaced in WITH-AI | 30 | 11 | “phish” 28, “lure” 2 |
| entry point | direct prompt by the user | exploit of a conventional software vulnerability | 28 | 18 | “prompt injection” 15, “system prompt” 9, “user input” 4 |
| entry point | stolen or leaked credential | exploit of a conventional software vulnerability | 26 | 24 | “credential” 23, “access token” 3 |

## Worked examples (12)

One label per record; the sentences are assembled from the files named at the top (rule match, corpus label, coder note, reviewer note). Each example was read again by two further independent reviewers, who agreed that the post value is the one the text supports.

1. **INC-15866** (ON-AI, cve/ghsa, 2026), entry point: *AWS HealthLake MCP Server SSRF via Pagination URL*  
   The keyword rule for 'stolen or leaked credential' matched “credential” in the text. The review changed it to 'exploit of a conventional software vulnerability': SSRF via crafted next_token is the entry; credential theft is the impact.

2. **INC-00898** (ON-AI, cve/ghsa, 2026), entry point: *Discourse — Prompt Injection (CVE-2026-27740)*  
   The keyword rule for 'direct prompt by the user' matched “Prompt Injection” in the text. The review changed it to 'indirect carrier (web/email/doc/tool output)': AI triage reads flagged forum post carrying injection; attacker does not prompt directly.

3. **INC-02870** (ON-AI, cve/ghsa, 2026), entry point: *RMCP — Vulnerability (CVE-2026-42559)*  
   The keyword rule for 'indirect carrier (web/email/doc/tool output)' matched “website” in the text. The review changed it to 'exploit of a conventional software vulnerability': Host header not validated; DNS rebinding is a conventional bug.

4. **INC-03607** (ON-AI, research/other, 2024), target: *Best-of-N Jailbreaking*  
   The keyword rule for 'consumer chatbot / hosted LLM app' matched “GPT-4” in the text. The review changed it to 'a model itself (vision, speech or text model attacked directly)': Jailbreak research on GPT-4o, Claude 3.5 Sonnet, Gemini, Llama.

5. **INC-00219** (ON-AI, harm-db, 2026), target: *AI System KURGAN Targets Massive Tax Fraud in Turkey*  
   No keyword rule matched and the corpus label maps to no single value, so pre is 'unstated'. The label-group rule then set 'other (tracker stub, no system named)' (the description is a tracker stub). The review changed it to 'no attacker: operator harm or model failure (misplaced record)': KURGAN is the detector, not a target; deployment story with no attack on AI.

6. **INC-01455** (ON-AI, harm-db, 2026), target: *Mistral AI Source Code Stolen in Major Data Breach*  
   No keyword rule matched and the corpus label maps to no single value, so pre is 'unstated'. The label-group rule then set 'other (tracker stub, no system named)' (the description is a tracker stub). The review changed it to 'other': Mistral company source code stolen; a company repository, not an AI system.

7. **INC-04816** (WITH-AI, harm-db, 2023), AI medium: *Purported Deepfake Video Falsely Depicts Biden Announcing National Draft for Ukraine*  
   The keyword rule for 'synthetic audio/voice' matched “Synthetic Audio” in the text. The review changed it to 'synthetic video': Title says deepfake video.

8. **INC-00512** (WITH-AI, harm-db, 2026), AI medium: *AI-Generated Videos Used in Religious Charity Scam in Taiwan*  
   No keyword rule matched; the corpus attack-vector label 'deepfake' maps to 'deepfake, medium not stated'. The review changed it to 'synthetic video': Title says AI-generated videos.

9. **INC-00675** (WITH-AI, harm-db, 2026), AI medium: *Baltimore Sues Elon Musk's xAI Over Grok Deepfake Harms*  
   No keyword rule matched; the corpus attack-vector label 'deepfake' maps to 'deepfake, medium not stated'. The review changed it to 'no attacker: operator harm or model failure (misplaced record)': Title is a city lawsuit against xAI; lawsuit story, no adversary described.

10. **INC-01504** (WITH-AI, cve/ghsa, 2026), AI medium: *n8n — Phishing (CVE-2026-42230)*  
   The keyword rule for 'generated text (phishing / lures / disinformation)' matched “Phish” in the text. The review changed it to 'none: conventional exploit record misplaced in WITH-AI': Open redirect CVE in n8n; no AI-generated content.

11. **INC-09141** (WITH-AI, cve/ghsa, 2026), objective: *MinIO has JWT Algorithm Confusion in OIDC Authentication*  
   The keyword rule for 'defamation / impersonation of a person' matched “Impersonat” in the text. The review changed it to 'intrusion / cyber operation': Forged tokens to obtain S3 credentials; intrusion.

12. **INC-00313** (WITH-AI, harm-db, 2026), objective: *AI-Driven Online Violence Against Women in Spain*  
   No keyword rule matched and the corpus label maps to no single value, so pre is 'unstated'. The two coders labelled it 'harassment or humiliation of a private person': Online violence against women; imagery type not stated in title. The review kept 'harassment or humiliation of a private person'.

## What the comparison says

- The review replaced 34.0% of the labels the first two steps had set (1,413 of 4,150); in 2026, 33.9% (681 of 2,009). With the filled labels, 51.1% of all labels and 53.1% of 2026 labels changed (Table 6.1).
- Entry point changed most (65.1% of labels); objective had the fewest replacements (11.6%), most of its change being filled labels (Table 6.1).
- Within a channel the 2026 change rate stays within 5.4 points of the all-years rate (largest gap: WITH-AI cve/ghsa, +5.4; channels with 50+ 2026 labels, Table 6.2): the 2026 cut needed as much correction as the whole record.
- The direction of the shifts is the same in both cuts: 6 values fell and 15 rose by 3+ points in both (Table 6.8).
- Where the 2026 post shares differ most from all years: entry point: exploit of a conventional software vulnerability 34.8% vs 26.4%; target: agent / copilot / coding assistant / MCP 57.5% vs 45.2%; AI medium: synthetic audio/voice 5.5% vs 14.6%; objective: political / influence 12.4% vs 19.0%.
- The no-attacker values and the CVE records in WITH-AI measure records the population split should not have admitted (step 2); they are kept as visible values in both cuts.

**Table 6.8. Values that moved 3+ points in the same direction in both cuts** (Δ = post − pre share, percentage points; from Tables 6.3–6.6)

| dimension | value | all years Δ | 2026 Δ |
|---|---|---|---|
| entry point | exploit of a conventional software vulnerability | +26.4 | +34.8 |
| AI medium | no attacker: operator harm or model failure (misplaced record) | +11.8 | +14.6 |
| objective | no attacker: operator harm or model failure (misplaced record) | +11.8 | +14.6 |
| target | a model itself (vision, speech or text model attacked directly) | +11.4 | +10.4 |
| entry point | no attacker: operator harm or model failure (misplaced record) | +9.6 | +8.8 |
| target | no attacker: operator harm or model failure (misplaced record) | +9.6 | +8.8 |
| AI medium | synthetic video | +9.5 | +5.8 |
| objective | intrusion / cyber operation | +8.6 | +11.2 |
| target | other | +7.8 | +6.6 |
| AI medium | other | +6.0 | +11.1 |
| AI medium | none: conventional exploit record misplaced in WITH-AI | +5.5 | +5.2 |
| entry point | other | +5.2 | +5.9 |
| objective | public deception, not political (hoax, fake news, clickbait) | +4.7 | +5.8 |
| entry point | via the agent's tools or sandbox | +3.4 | +4.7 |
| target | ML/LLM framework or serving library | +3.2 | +3.3 |
| AI medium | deepfake, medium not stated | −15.8 | −17.2 |
| entry point | direct prompt by the user | −9.4 | −11.0 |
| target | consumer chatbot / hosted LLM app | −9.0 | −8.8 |
| AI medium | generated text (phishing / lures / disinformation) | −4.1 | −3.4 |
| AI medium | synthetic image | −3.6 | −5.2 |
| entry point | stolen or leaked credential | −3.5 | −6.2 |
